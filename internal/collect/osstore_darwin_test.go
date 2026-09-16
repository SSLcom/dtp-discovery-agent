//go:build darwin

package collect

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The subprocess path, run for real: /usr/bin/security against the keychain a
// daemon on this machine would read. Cross-compiling proves this file parses;
// only running it proves the tool is where we say it is, takes the arguments we
// give it, and writes PEM to stdout.
func TestReadsTheRealSystemKeychain(t *testing.T) {
	out, err := runSecurity(context.Background(), "find-certificate", "-a", "-p",
		"/Library/Keychains/System.keychain")
	if err != nil {
		t.Fatalf("reading the system keychain: %v", err)
	}
	// A system keychain with no certificates in it is perfectly normal on a
	// fresh machine, so an empty result is a successful read — what is being
	// checked is that the tool ran and said something we can parse.
	if out != "" && !strings.Contains(out, "BEGIN CERTIFICATE") {
		t.Errorf("security returned something that is not PEM: %.120q", out)
	}
}

// The trust store is several hundred CA certificates and is not deployed on
// this machine. Naming it here would put all of them in a member's portfolio.
func TestTheSystemRootsKeychainIsNotOneOfTheDefaults(t *testing.T) {
	for _, keychain := range defaultDarwinKeychains {
		if strings.Contains(keychain, "SystemRootCertificates") {
			t.Errorf("%s is the trust store, not a list of what this machine serves", keychain)
		}
	}
}

// A keychain that is not there must be reported rather than silently dropped:
// the agent did not see what was in it.
func TestAKeychainThatCannotBeReadIsReported(t *testing.T) {
	_, failures, err := readOSStores(context.Background(),
		[]string{"/Library/Keychains/no-such-keychain-exists.keychain"})
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 1 {
		t.Fatalf("got %d failures, want the one unreadable keychain", len(failures))
	}
	if failures[0].Err == nil || failures[0].Err.Error() == "" {
		t.Error("the reason has to reach the member")
	}
}

// The agent runs unattended. A subprocess that blocked — waiting for a prompt,
// or on a keychain that will not answer — must not hold a scan open for ever.
func TestTheSubprocessIsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Already done before it starts.

	start := time.Now()
	if _, err := runSecurity(ctx, "find-certificate", "-a", "-p",
		"/Library/Keychains/System.keychain"); err == nil {
		t.Error("a cancelled scan should not keep reading keychains")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("took %s to give up on a cancelled context", elapsed)
	}
}
