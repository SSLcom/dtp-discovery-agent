//go:build windows

package collect

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Reading the machine's OWN Root store. It is on every Windows installation and
// holds hundreds of certificates, so it exercises the whole path — opening the
// store, walking it, and copying each certificate out of a context that the
// next call frees — against real data rather than a fixture.
func TestReadsTheMachinesRealRootStore(t *testing.T) {
	entries, err := readWindowsStore(`LocalMachine\Root`)
	if err != nil {
		t.Fatalf("reading the machine's root store: %v", err)
	}
	if len(entries) < 5 {
		t.Fatalf("got %d certificates from LocalMachine\\Root; every Windows install has many", len(entries))
	}

	for _, entry := range entries {
		if entry.Certificate == nil || len(entry.Certificate.Raw) == 0 {
			t.Fatal("a certificate came back with no DER")
		}
		// THE COPY IS WHAT THIS PROVES. x509.ParseCertificate keeps the slice it
		// was handed as cert.Raw, and that memory belongs to the certificate
		// context, which the next enumeration call frees. Without the copy these
		// certificates would be pointing at memory Windows had reclaimed — and
		// re-parsing what we kept is how that would show up.
		if _, err := parseAgain(entry.Certificate.Raw); err != nil {
			t.Fatalf("a certificate held after enumeration no longer parses: %v", err)
		}
	}
}

// The trust anchors have to be dropped before they reach a member's portfolio:
// there are hundreds per machine and none of them is deployed on it.
func TestTheRootStoreContributesNothingToTheInventory(t *testing.T) {
	res := (&OSStore{Stores: []string{`LocalMachine\Root`}}).Collect(context.Background())

	if len(res.Observations) != 0 {
		t.Fatalf("the root store yielded %d observations; it is a list of issuers", len(res.Observations))
	}
	if !res.Completed || len(res.Errors) != 0 {
		t.Errorf("reading it is not a fault: completed=%v errors=%v", res.Completed, res.Errors)
	}
}

// WebHosting exists only where IIS 8 or later is installed, so on most machines
// it is simply absent. That has to be as quiet as a web server not being
// installed, or every non-IIS Windows host reports an error for ever.
func TestAStoreThatIsNotOnThisMachineIsNotAFailure(t *testing.T) {
	_, failures, err := readOSStores(context.Background(),
		[]string{`LocalMachine\NoSuchStoreExistsHere`})
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 0 {
		t.Errorf("an absent store was reported as a failure: %v", failures)
	}
}

func TestStoreNamesAreParsedIntoALocationAndAStore(t *testing.T) {
	for _, bad := range []string{"", "My", `Nowhere\My`, `\`} {
		if _, _, err := splitWindowsStoreName(bad); err == nil {
			t.Errorf("%q was accepted as a store name", bad)
		}
	}
	if _, store, err := splitWindowsStoreName(`LocalMachine\Remote Desktop`); err != nil || store != "Remote Desktop" {
		t.Errorf("got %q, %v; a store name may contain a space", store, err)
	}
}

// The end-to-end case, and the one IIS depends on: a certificate this machine
// holds the KEY for. Without that flag a web server's own certificate and a
// trust anchor somebody imported are indistinguishable, because on Windows they
// sit in the same kind of store.
//
// The certificate is built HERE and imported with certutil, rather than made by
// New-SelfSignedCertificate. The cmdlet needs the PowerShell `Cert:` drive, and
// on the CI runner that drive is not registered — "A drive with the name 'Cert'
// does not exist", measured. certutil is a native executable with no such
// dependency, and building the certificate in Go means the test knows exactly
// what it is looking for.
//
// Only in CI. It writes to the current user's certificate store, which is not
// something to do to a developer's machine unasked, and removes it afterwards.
func TestFindsACertificateThisMachineHoldsTheKeyFor(t *testing.T) {
	if os.Getenv("CI") == "" {
		t.Skip("writes to CurrentUser\\My; runs on the Windows CI runner")
	}

	// A REAL PASSWORD, not an empty one. `certutil -p ""` does not mean "no
	// password" to certutil — it prompts, and on the CI runner it sat there
	// until the whole test binary hit its ten-minute limit and panicked.
	const password = "dtp-agent-test-password"

	cert, pfx := selfSignedPFX(t, "dtp-agent-test.invalid", password)
	path := filepath.Join(t.TempDir(), "test.pfx")
	if err := os.WriteFile(path, pfx, 0o600); err != nil {
		t.Fatal(err)
	}

	want := thumbprint(cert)
	if out, err := run(t, "certutil", "-user", "-f", "-p", password, "-importpfx", "My", path); err != nil {
		t.Fatalf("importing the test certificate: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if out, err := run(t, "certutil", "-user", "-delstore", "My", want); err != nil {
			t.Logf("could not remove the test certificate %s: %v\n%s", want, err, out)
		}
	})

	res := (&OSStore{Stores: []string{`CurrentUser\My`}}).Collect(context.Background())

	for _, obs := range res.Observations {
		if obs.Binding["thumbprint"] != want {
			continue
		}
		if !obs.PrivateKeyPresent {
			t.Error("a certificate imported with its key was reported as having none")
		}
		if obs.PrivateKeyLocation != `CurrentUser\My` {
			t.Errorf("key location = %q; the store holds the key, so the store is the location", obs.PrivateKeyLocation)
		}
		if !strings.Contains(obs.CertificatePEM, "BEGIN CERTIFICATE") {
			t.Error("the observation carried no PEM")
		}
		return
	}
	t.Fatalf("the certificate at %s was not found; the store yielded %d observations", want, len(res.Observations))
}

// selfSignedPFX is a certificate and its key, in the form certutil imports.
func selfSignedPFX(t *testing.T, cn, password string) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pfx, err := pkcs12.Modern.Encode(key, cert, nil, password)
	if err != nil {
		t.Fatal(err)
	}
	return cert, pfx
}

// run bounds the subprocess. A tool that decides to prompt has no one to answer
// it here, and the first version of this test let certutil sit on a hidden
// prompt until the entire test binary hit its ten-minute limit and panicked —
// taking every other test's result with it. A minute is generous for certutil
// and short enough to leave a readable failure.
func run(t *testing.T, name string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(out), fmt.Errorf("%s did not finish within a minute (it is probably waiting for input): %w", name, ctx.Err())
	}
	return string(out), err
}
