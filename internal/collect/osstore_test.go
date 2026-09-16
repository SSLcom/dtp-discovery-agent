package collect

import (
	"context"
	"crypto/x509"
	"errors"
	"runtime"
	"strings"
	"testing"
)

// withStores replaces the platform reader for the duration of a test, so the
// decisions made above it are checked everywhere rather than only on the one
// platform they happen to run on.
func withStores(t *testing.T, fn func(context.Context, []string) ([]storeEntry, []storeFailure, error)) {
	t.Helper()
	original := osStores
	t.Cleanup(func() { osStores = original })
	osStores = fn
}

func certFor(t *testing.T, cn string, isCA bool) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(makeCert(t, cn, isCA))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// Every machine's store holds hundreds of trust anchors and a handful of
// certificates it actually serves. Reporting the anchors drowns the ones a
// member is paying to keep track of, in a ratio of about a hundred to one.
func TestTrustAnchorsInAStoreAreNotDeployments(t *testing.T) {
	withStores(t, func(context.Context, []string) ([]storeEntry, []storeFailure, error) {
		return []storeEntry{
			{Store: `LocalMachine\Root`, Certificate: certFor(t, "Some Root CA", true)},
			{Store: `LocalMachine\Root`, Certificate: certFor(t, "Some Intermediate", true)},
			{Store: `LocalMachine\My`, Certificate: certFor(t, "www.example.com", false), HasPrivateKey: true,
				FriendlyName: "Production web certificate"},
		}, nil, nil
	})

	res := (&OSStore{}).Collect(context.Background())
	if len(res.Observations) != 1 {
		t.Fatalf("got %d observations, want only the served certificate", len(res.Observations))
	}
	obs := res.Observations[0]
	if obs.Location != `LocalMachine\My` {
		t.Errorf("location = %q; the STORE is the placement, since several certificates share one", obs.Location)
	}
	// The thumbprint is what `netsh http show sslcert` prints and what the
	// certificates snap-in displays, so a finding can be matched against what
	// an administrator sees on their own screen.
	if len(obs.Binding["thumbprint"]) != 40 {
		t.Errorf("thumbprint = %q, want 40 hex characters", obs.Binding["thumbprint"])
	}
	if obs.Binding["friendly_name"] != "Production web certificate" {
		t.Errorf("binding lost the administrator's own label: %v", obs.Binding)
	}
	// The key is held BY the store — on Windows often by a hardware provider
	// behind it — so there is no file to send an operator to.
	if !obs.PrivateKeyPresent || obs.PrivateKeyLocation != `LocalMachine\My` {
		t.Errorf("key present=%v at %q", obs.PrivateKeyPresent, obs.PrivateKeyLocation)
	}
	if !res.Completed {
		t.Errorf("every store read cleanly: %v", res.Errors)
	}
}

// A store that would not open holds certificates the agent did not see. Calling
// that a complete sweep lets a later run conclude they were removed from a
// machine where they are sitting untouched.
func TestAStoreThatWouldNotOpenStopsTheSweep(t *testing.T) {
	withStores(t, func(context.Context, []string) ([]storeEntry, []storeFailure, error) {
		return []storeEntry{{Store: `LocalMachine\My`, Certificate: certFor(t, "www.example.com", false), HasPrivateKey: true}},
			[]storeFailure{{Store: `LocalMachine\WebHosting`, Err: errors.New("access is denied")}}, nil
	})

	res := (&OSStore{}).Collect(context.Background())
	if len(res.Observations) != 1 {
		t.Errorf("what WAS read is still worth reporting: got %d", len(res.Observations))
	}
	if res.Completed {
		t.Error("certificates the agent could not see must not become certificates that were removed")
	}
	if len(res.Errors) == 0 || !strings.Contains(res.Errors[0].Error, "access is denied") {
		t.Errorf("the reason must reach the member: %v", res.Errors)
	}
}

// Most hosts this runs on are Linux, where there is no such store. That is a
// fact about the platform, not a fault, so it must be silent — but the source
// still cannot claim a sweep it never did.
func TestAPlatformWithNoStoreIsSilentButNeverComplete(t *testing.T) {
	withStores(t, func(context.Context, []string) ([]storeEntry, []storeFailure, error) {
		return nil, nil, errNoOSStoreForTest()
	})

	res := (&OSStore{}).Collect(context.Background())
	if len(res.Observations) != 0 || len(res.Errors) != 0 {
		t.Errorf("got %v / %v, want silence", res.Observations, res.Errors)
	}
	if res.Completed {
		t.Error("a source that cannot run here has swept nothing")
	}
}

// This is the real thing on Linux, not a stand-in: /etc/ssl/certs is files, and
// the filesystem collector already reads them. Reporting them again as an "OS
// store" would give a member two rows to reconcile for one certificate.
func TestOnLinuxTheCollectorIsACleanNoOp(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		t.Skipf("%s has a real store", runtime.GOOS)
	}
	res := (&OSStore{}).Collect(context.Background())
	if len(res.Observations) != 0 || len(res.Errors) != 0 || res.Completed {
		t.Errorf("got %v / %v / completed=%v", res.Observations, res.Errors, res.Completed)
	}
}

// `security find-identity -v` is how the agent tells a certificate a Mac can
// SERVE from one somebody imported to trust. Parsed here rather than beside the
// rest of the macOS code so it is exercised on every runner.
func TestIdentityListingIsReadForItsThumbprints(t *testing.T) {
	out := `  1) 8E7D4C1A9B2F3E5D6C7B8A90112233445566778899 "Developer ID"
  2) A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 "www.example.com"
  3) 0123456789ABCDEF0123456789ABCDEF01234567 "internal.example.com" (CSSMERR_TP_CERT_EXPIRED)
     2 identities found

  Valid identities only`

	got := parseIdentities(out)

	// The first line's hash is 43 characters — not a thumbprint, and taking it
	// would mark an unrelated certificate as one this machine holds a key for.
	if len(got) != 2 {
		t.Fatalf("got %d identities, want 2: %v", len(got), got)
	}
	for _, want := range []string{"A1B2C3D4E5F60718293A4B5C6D7E8F9012345678", "0123456789ABCDEF0123456789ABCDEF01234567"} {
		if !got[want] {
			t.Errorf("%s was not read as an identity", want)
		}
	}
	// An EXPIRED identity still counts: the machine holds the key, and an
	// expired certificate it is still serving is the finding, not a thing to
	// quietly drop.
	if !got["0123456789ABCDEF0123456789ABCDEF01234567"] {
		t.Error("an expired identity is still an identity")
	}
}

func errNoOSStoreForTest() error {
	return errors.New("this platform has no operating system certificate store")
}

// basicConstraints alone is not enough to recognise a trust anchor, and this
// was measured rather than reasoned about: on a Windows runner, fourteen
// certificates in LocalMachine\Root carry no basicConstraints extension at all,
// so Go reports IsCA false for every one of them. Without a second test they
// would arrive in a member's portfolio as deployed certificates, from every
// Windows host they own.
//
// The private key is what tells the two apart. Internal infrastructure is full
// of self-signed SERVER certificates, and a machine holding the key for one is
// serving it.
// A store whose purpose is trust anchors holds nothing this machine serves,
// whatever shape the certificates in it are. Measured: two certificates in a
// Windows Root store are cross-signed, so they are neither self-signed nor
// flagged as CAs, and nothing about their contents gives them away.
func TestEverythingInAnAnchorStoreIsAnAnchor(t *testing.T) {
	for _, store := range []string{`LocalMachine\Root`, `LocalMachine\CA`, `CurrentUser\AuthRoot`,
		`LocalMachine\Disallowed`, "/System/Library/Keychains/SystemRootCertificates.keychain"} {
		// A certificate that would otherwise read as a deployment: not a CA,
		// issued by somebody else, and with a key.
		entry := storeEntry{Store: store, Certificate: caSignedLeaf(t), HasPrivateKey: true}
		if !trustAnchor(entry) {
			t.Errorf("%s exists to hold anchors; nothing in it is deployed here", store)
		}
	}
	// And a store that holds what the machine serves is not one of them.
	for _, store := range []string{`LocalMachine\My`, `LocalMachine\WebHosting`, "/Library/Keychains/System.keychain"} {
		entry := storeEntry{Store: store, Certificate: caSignedLeaf(t), HasPrivateKey: true}
		if trustAnchor(entry) {
			t.Errorf("%s is where a served certificate lives", store)
		}
	}
}

func TestASelfSignedCertificateIsAnAnchorOrADeploymentAccordingToTheKey(t *testing.T) {
	// Deliberately NOT an anchor store. This is checking what the CERTIFICATE
	// says; putting it in Root would let the assertion pass for the store
	// rule's reason instead.
	selfSignedNoKey := storeEntry{
		Store: `LocalMachine\My`, Certificate: certFor(t, "An Old Root", false),
	}
	if !trustAnchor(selfSignedNoKey) {
		t.Error("a self-signed certificate this machine has no key for is an issuer it believes, not something it serves")
	}

	selfSignedWithKey := selfSignedNoKey
	selfSignedWithKey.HasPrivateKey = true
	if trustAnchor(selfSignedWithKey) {
		t.Error("a self-signed certificate this machine holds the key for is deployed on it")
	}

	// And the ordinary case stays ordinary. An INTERMEDIATE is the one that
	// needs saying: it is a CA and it is not self-signed, so only the
	// basicConstraints test catches it. A self-signed root would be caught by
	// the rule above and would let that test pass for the wrong reason.
	intermediate := caSignedIntermediate(t)
	if !trustAnchor(storeEntry{Certificate: intermediate}) {
		t.Error("an intermediate CA is an anchor, not something this machine serves")
	}
	if trustAnchor(storeEntry{Certificate: caSignedLeaf(t), HasPrivateKey: true}) {
		t.Error("a certificate issued by somebody else is not an anchor")
	}
}
