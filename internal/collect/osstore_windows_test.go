//go:build windows

package collect

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
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
// Only in CI. It writes to the current user's certificate store, which is not
// something to do to a developer's machine unasked, and cleans up after itself.
func TestFindsACertificateThisMachineHoldsTheKeyFor(t *testing.T) {
	if os.Getenv("CI") == "" {
		t.Skip("writes to CurrentUser\\My; runs on the Windows CI runner")
	}

	const subject = "dtp-agent-test.invalid"
	thumb, err := powershell(fmt.Sprintf(
		`$c = New-SelfSignedCertificate -Subject "CN=%s" -CertStoreLocation Cert:\CurrentUser\My `+
			`-FriendlyName "dtp-agent test certificate" -NotAfter (Get-Date).AddDays(1); `+
			`$c.Thumbprint`, subject))
	if err != nil {
		t.Skipf("could not create a test certificate: %v", err)
	}
	thumb = strings.ToUpper(strings.TrimSpace(thumb))
	t.Cleanup(func() {
		_, _ = powershell(fmt.Sprintf(`Remove-Item -Path Cert:\CurrentUser\My\%s -Force`, thumb))
	})

	res := (&OSStore{Stores: []string{`CurrentUser\My`}}).Collect(context.Background())

	for _, obs := range res.Observations {
		if obs.Binding["thumbprint"] != thumb {
			continue
		}
		if !obs.PrivateKeyPresent {
			t.Error("a certificate created with its key was reported as having none")
		}
		if obs.Binding["friendly_name"] != "dtp-agent test certificate" {
			t.Errorf("friendly name = %q; it is often the only human-readable label on a Windows certificate",
				obs.Binding["friendly_name"])
		}
		if !strings.Contains(obs.CertificatePEM, "BEGIN CERTIFICATE") {
			t.Error("the observation carried no PEM")
		}
		return
	}
	t.Fatalf("the certificate at %s was not found; the store yielded %d observations", thumb, len(res.Observations))
}

func powershell(script string) (string, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	return string(out), err
}
