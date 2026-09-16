//go:build darwin

package collect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/SSLcom/dtp-discovery-agent/internal/parse"
)

// The keychain a SERVICE on this machine reads. A login keychain belongs to a
// person and is unlocked by them; a daemon terminating TLS uses the system one.
//
// SystemRootCertificates.keychain is deliberately absent: it is the trust store,
// several hundred CA certificates, and none of them is deployed here.
var defaultDarwinKeychains = []string{
	"/Library/Keychains/System.keychain",
}

// securityTool is Apple's own command-line front end to the keychain.
//
// A SUBPROCESS, WHICH IS NOT THIS AGENT'S HABIT, and the reason is worth
// stating: reading a keychain means Security.framework, which means cgo, and
// cgo would end the single portable static binary this whole thing ships as —
// it would link the build machine's libc and acquire a version requirement from
// it. Parsing the keychain file format directly is the other option, and it is
// undocumented and changes between releases. So: the tool Apple ships, at an
// absolute path, with a timeout, reading only public objects.
const securityTool = "/usr/bin/security"

const securityTimeout = 30 * time.Second

func readOSStores(ctx context.Context, only []string) ([]storeEntry, []storeFailure, error) {
	keychains := only
	if len(keychains) == 0 {
		keychains = defaultDarwinKeychains
	}

	// Which certificates this machine holds the KEY for. Without it the
	// certificate a service serves and one somebody imported to trust are
	// indistinguishable, and every keychain on every Mac would report the same
	// undifferentiated pile.
	identities := keychainIdentities(ctx)

	var (
		entries  []storeEntry
		failures []storeFailure
	)
	for _, keychain := range keychains {
		if ctx.Err() != nil {
			return entries, failures, ctx.Err()
		}

		// ASKED BEFORE RUNNING THE TOOL, because `security find-certificate`
		// exits ZERO and prints nothing for a keychain that is not there —
		// measured on a macOS runner. Without this check, a system keychain that
		// had been moved, renamed or made unreadable would read as a keychain
		// with no certificates in it, the sweep would be declared complete, and
		// every certificate the machine serves would be marked as removed.
		if _, statErr := os.Stat(keychain); statErr != nil {
			failures = append(failures, storeFailure{Store: keychain, Err: statErr})
			continue
		}

		out, err := runSecurity(ctx, "find-certificate", "-a", "-p", keychain)
		if err != nil {
			failures = append(failures, storeFailure{Store: keychain, Err: err})
			continue
		}
		// `security` prints nothing at all for an empty keychain, which is a
		// successful read of a keychain with no certificates in it.
		parsed, err := parse.Certificates([]byte(out))
		if err != nil {
			continue
		}
		for _, cert := range parsed.Certificates {
			entries = append(entries, storeEntry{
				Store:         keychain,
				Certificate:   cert,
				HasPrivateKey: identities[thumbprint(cert)],
			})
		}
	}
	return entries, failures, nil
}

// keychainIdentities is the set of certificate thumbprints this machine has a
// matching private key for. `security find-identity` is what knows: an identity
// is precisely a certificate paired with its key.
//
// A failure here is not a failure of the sweep. It costs the private_key_present
// flag, not a certificate, so it degrades rather than hiding a finding.
func keychainIdentities(ctx context.Context) map[string]bool {
	out, err := runSecurity(ctx, "find-identity", "-v")
	if err != nil {
		return nil
	}
	return parseIdentities(out)
}

func runSecurity(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, securityTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, securityTool, args...)
	// No stdin. Nothing here should ever be able to prompt, and a subprocess
	// that blocked waiting for one on an unattended machine would hang the
	// scan until the timeout for no reason anybody could see.
	cmd.Stdin = nil

	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return "", fmt.Errorf("security %s: %s", args[0], strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", fmt.Errorf("security %s: %w", args[0], err)
	}
	return string(out), nil
}
