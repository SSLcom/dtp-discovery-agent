package collect

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures are keytool's own output; see internal/parse/testdata/README.md.
func keystoreFixture(t *testing.T, name, into string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(into, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func collectKeystores(t *testing.T, root string) Result {
	t.Helper()
	c := &Keystores{Bounds: KeystoreBounds{Roots: []string{root}}}
	return c.Collect(context.Background())
}

func locations(res Result) []string {
	out := make([]string, 0, len(res.Observations))
	for _, o := range res.Observations {
		out = append(out, o.Location)
	}
	return out
}

// A Tomcat's certificate is in a .jks, which is neither PEM nor DER — so to
// every other collector a Java host terminating TLS looks like a machine with
// no certificates on it at all.
func TestFindsTheCertificatesInsideAJavaKeystore(t *testing.T) {
	root := t.TempDir()
	path := keystoreFixture(t, "real.jks", filepath.Join(root, "conf"))

	res := collectKeystores(t, root)
	if !res.Completed {
		t.Errorf("a keystore that read cleanly is a complete sweep: %v", res.Errors)
	}
	if len(res.Observations) != 3 {
		t.Fatalf("got %v, want the three aliases keytool put there", locations(res))
	}

	byAlias := map[string]Observation{}
	for _, o := range res.Observations {
		byAlias[o.Binding["alias"]] = o
	}
	for _, alias := range []string{"tomcat", "other", "trustedroot"} {
		obs, ok := byAlias[alias]
		if !ok {
			t.Errorf("alias %q missing; got %v", alias, locations(res))
			continue
		}
		// The alias, not just the file: it is what `keytool -delete -alias`
		// takes, and on a store with six aliases it is the only thing that says
		// which one is expiring.
		if want := path + ":" + alias; obs.Location != want {
			t.Errorf("location = %q, want %q", obs.Location, want)
		}
		if obs.Binding["keystore"] != path || obs.Binding["format"] != "jks" {
			t.Errorf("%s: binding = %v", alias, obs.Binding)
		}
	}

	// A PrivateKeyEntry holds a key and the key is INSIDE the store, so the
	// store is where an operator has to go. A trustedCertEntry holds none, and
	// saying it did would claim this host can serve a certificate it cannot.
	if !byAlias["tomcat"].PrivateKeyPresent || byAlias["tomcat"].PrivateKeyLocation != path {
		t.Errorf("tomcat: key present=%v at %q", byAlias["tomcat"].PrivateKeyPresent, byAlias["tomcat"].PrivateKeyLocation)
	}
	if byAlias["trustedroot"].PrivateKeyPresent || byAlias["trustedroot"].PrivateKeyLocation != "" {
		t.Error("a trustedCertEntry has no key and must not claim one")
	}
}

func TestFindsAJCEKSKeystoreToo(t *testing.T) {
	root := t.TempDir()
	keystoreFixture(t, "real.jceks", root)

	res := collectKeystores(t, root)
	if len(res.Observations) != 1 {
		t.Fatalf("got %v, want the one jceks entry", locations(res))
	}
	if res.Observations[0].Binding["format"] != "jceks" {
		t.Errorf("format = %q, want jceks", res.Observations[0].Binding["format"])
	}
}

// Every host with a JDK has a cacerts, and it is a hundred and fifty CA
// certificates. Reporting it as a deployment buries the certificates a member
// is paying to track under the list of issuers their JDK happens to ship with.
func TestATrustStoreContributesNothingToTheInventory(t *testing.T) {
	root := t.TempDir()
	keystoreFixture(t, "truststore.jks", filepath.Join(root, "lib", "security"))

	res := collectKeystores(t, root)
	if len(res.Observations) != 0 {
		t.Fatalf("a trust store is a list of issuers, not a deployment: got %v", locations(res))
	}
	// Silently, too. It is on every host, so an error here would be an error
	// everywhere.
	if len(res.Errors) != 0 {
		t.Errorf("reading a trust store is not a fault: %v", res.Errors)
	}
	if !res.Completed {
		t.Error("nothing here should spoil the sweep")
	}
}

// `cacerts` has no extension at all. Matching only on extension misses the one
// keystore every JDK ships — and it is the file most likely to be mistaken for
// a deployment if it were read carelessly.
func TestAFileNamedCacertsIsRecognisedWithoutAnExtension(t *testing.T) {
	root := t.TempDir()
	data, err := os.ReadFile(filepath.Join("testdata", "real.jks"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "cacerts")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	if res := collectKeystores(t, root); len(res.Observations) != 3 {
		t.Fatalf("a file named cacerts was not opened: got %v", locations(res))
	}
}

// A directory full of ordinary files must not produce findings or noise. These
// roots are shared with configuration, logs and jars.
func TestFilesThatAreNotKeystoresAreSilent(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"server.xml":      "<Server/>",
		"app.jks":         "this file is named like a keystore and is not one",
		"notes.keystore":  "",
		"random.p12":      "not a PKCS#12 either",
		"application.jar": "PK\x03\x04 and some bytes",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	res := collectKeystores(t, root)
	if len(res.Observations) != 0 || len(res.Errors) != 0 {
		t.Fatalf("got %v / %v, want silence", locations(res), res.Errors)
	}
	if !res.Completed {
		t.Error("files that are not keystores must not spoil the sweep")
	}
}

// A store the agent could only partly read holds aliases it never saw, and
// those must not be treated as removed. What it DID read is still real.
func TestAPartlyReadableKeystoreReportsWhatItGotAndStopsTheSweep(t *testing.T) {
	root := t.TempDir()
	data, err := os.ReadFile(filepath.Join("testdata", "real.jks"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "truncated.jks"), data[:len(data)-200], 0o644); err != nil {
		t.Fatal(err)
	}

	res := collectKeystores(t, root)
	if len(res.Observations) == 0 {
		t.Error("the aliases read before the damage were thrown away")
	}
	if len(res.Errors) == 0 {
		t.Error("a member has to be told the store was only partly read")
	}
	if res.Completed {
		t.Error("aliases the agent never saw must not be treated as removed")
	}
}

func TestAKeystoreThatCannotBeReadStopsTheSweep(t *testing.T) {
	requireUnprivileged(t)
	root := t.TempDir()
	path := keystoreFixture(t, "real.jks", root)
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}

	res := collectKeystores(t, root)
	if res.Completed || len(res.Errors) == 0 {
		t.Fatal("a keystore the agent could not open is unseen, not empty")
	}
	if !strings.Contains(res.Errors[0].Error, "permission denied") {
		t.Errorf("the reason should reach the member: %q", res.Errors[0].Error)
	}
}

// The whole point of reading the format directly rather than taking a library:
// a key entry's encrypted blob is stepped over by length and never held.
func TestNoKeyMaterialLeavesAKeystore(t *testing.T) {
	root := t.TempDir()
	keystoreFixture(t, "real.jks", root)

	for _, o := range collectKeystores(t, root).Observations {
		if strings.Contains(strings.ToUpper(o.CertificatePEM+o.ChainPEM), "PRIVATE KEY") {
			t.Fatal("key material reached an observation")
		}
	}
}

// keystoreWithKeyAndNoChain builds a JKS holding one PrivateKeyEntry whose
// certificate chain is EMPTY. keytool does not normally write one, but the
// format permits chainLen 0 — and a key entry whose certificates all fail to
// parse arrives at the collector identically, because one unreadable
// certificate must not invalidate the aliases around it.
func keystoreWithKeyAndNoChain(t *testing.T, alias string) []byte {
	t.Helper()
	var b []byte
	u32 := func(v uint32) {
		var x [4]byte
		binary.BigEndian.PutUint32(x[:], v)
		b = append(b, x[:]...)
	}
	utf := func(s string) {
		var x [2]byte
		binary.BigEndian.PutUint16(x[:], uint16(len(s)))
		b = append(b, x[:]...)
		b = append(b, s...)
	}

	u32(0xFEEDFEED) // magic
	u32(2)          // version
	u32(1)          // one entry
	u32(1)          // tag: private key
	utf(alias)
	b = append(b, make([]byte, 8)...) // creation date
	u32(4)                            // key length
	b = append(b, 0xDE, 0xAD, 0xBE, 0xEF)
	u32(0)                             // CHAIN LENGTH ZERO
	b = append(b, make([]byte, 20)...) // trailing digest
	return b
}

// Found by Bugbot on the branch, and it PANICKED: the private-key exception
// added here indexed Certificates[0] after parse.Leaf found nothing, and a key
// entry can hold no certificate at all. Collect has no recover, so one odd
// alias aborted the scan of the entire host — every other collector's findings
// with it.
func TestAKeyEntryWithNoCertificateIsSkippedRatherThanFatal(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "keyonly.jks"),
		keystoreWithKeyAndNoChain(t, "keyonly"), 0o644); err != nil {
		t.Fatal(err)
	}

	var res Result
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("a keystore entry with no certificate panicked the scan: %v", r)
			}
		}()
		res = collectKeystores(t, root)
	}()

	// There is nothing to inventory in a key with no certificate, so silence is
	// the right answer — not an error a member can do nothing about.
	if len(res.Observations) != 0 {
		t.Errorf("reported %d observations for an entry holding no certificate", len(res.Observations))
	}
	if !res.Completed {
		t.Errorf("an entry with no certificate did not stop this sweep seeing everything: %v", res.Errors)
	}
}

// The neighbours still have to be read. The whole reason a key entry can arrive
// with no certificate is that the parser skips one it cannot decode rather than
// abandoning the file, and that is only worth doing if what follows survives.
func TestAnAliasWithNoCertificateDoesNotHideTheOnesAroundIt(t *testing.T) {
	root := t.TempDir()
	good := keystoreFixture(t, "real.jks", root)
	if err := os.WriteFile(filepath.Join(root, "keyonly.jks"),
		keystoreWithKeyAndNoChain(t, "keyonly"), 0o644); err != nil {
		t.Fatal(err)
	}

	res := collectKeystores(t, root)

	found := 0
	for _, o := range res.Observations {
		if o.Binding["keystore"] == good {
			found++
		}
	}
	if found != 3 {
		t.Fatalf("got %d observations from the good keystore, want its 3 aliases: %v", found, locations(res))
	}
}
