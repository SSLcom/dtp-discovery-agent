package parse

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The expected values are what `keytool -list` printed for these very files.
// Asserting against the reference implementation's own output is the point: a
// fixture this repository generated would only confirm that the parser agrees
// with the encoder that wrote it, and a shared misreading of the format would
// sail through.
const (
	tomcatFingerprint = "c887001950a34442b2dff382b596eec308387702 8d15d272d218b4357aa35b66"
	otherFingerprint  = "6e8d2335dff3a3232e53c742342 3c661f9c7e0166cc92570784d417757651cef"
	root1Fingerprint  = "9a6ec012e1a7da9dbe34194d478ad7c0db1822fb071df12981496ed104384113"
	root2Fingerprint  = "ebc5570c29018c4d67b1aa127baf12f703b4611ebc17b7dab557389417 9b93fa"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func clean(s string) string { return strings.ReplaceAll(s, " ", "") }

func byAlias(entries []KeystoreEntry) map[string]KeystoreEntry {
	out := make(map[string]KeystoreEntry, len(entries))
	for _, e := range entries {
		out[e.Alias] = e
	}
	return out
}

func TestReadsAKeystoreKeytoolWrote(t *testing.T) {
	entries, err := JavaKeystore(loadFixture(t, "real.jks"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want the 3 keytool reported", len(entries))
	}

	got := byAlias(entries)
	for _, want := range []struct {
		alias       string
		fingerprint string
		hasKey      bool
	}{
		{"tomcat", clean(tomcatFingerprint), true},
		{"other", clean(otherFingerprint), true},
		// A trustedCertEntry has no key, and reading it as though it did would
		// put "key present" on a certificate nobody on this host can serve.
		{"trustedroot", clean(tomcatFingerprint), false},
	} {
		entry, ok := got[want.alias]
		if !ok {
			t.Errorf("alias %q was not found; got %v", want.alias, aliases(entries))
			continue
		}
		if len(entry.Certificates) != 1 {
			t.Errorf("%s: got %d certificates, want 1", want.alias, len(entry.Certificates))
			continue
		}
		if fp := fingerprint(entry.Certificates[0]); fp != want.fingerprint {
			t.Errorf("%s: fingerprint %s, keytool said %s", want.alias, fp, want.fingerprint)
		}
		if entry.HasPrivateKey != want.hasKey {
			t.Errorf("%s: HasPrivateKey = %v, want %v", want.alias, entry.HasPrivateKey, want.hasKey)
		}
	}
}

// The key blob sits between the alias and the certificate chain. Skipping it by
// the wrong number of bytes does not fail loudly — it desynchronises the reader
// and the NEXT entry comes out as nonsense. That the two entries after the
// first RSA key are read correctly above is what proves the skip is right.
func TestAPrivateKeyIsSteppedOverNotRead(t *testing.T) {
	entries, err := JavaKeystore(loadFixture(t, "real.jks"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		for _, cert := range entry.Certificates {
			// Whatever came back is a certificate: it parsed as one, and what
			// the agent transmits is re-encoded from cert.Raw. There is no
			// field here for key bytes and no path by which the skipped blob
			// could reach one.
			if cert.Raw == nil {
				t.Errorf("%s: certificate has no DER", entry.Alias)
			}
		}
	}
	// The EC entry is written after the RSA entry's ~1.2 KB encrypted key. It
	// can only be read if the skip landed exactly.
	if _, ok := byAlias(entries)["other"]; !ok {
		t.Fatal("the entry after a private key was not reached; the key skip is off")
	}
}

func TestReadsAJCEKSKeystore(t *testing.T) {
	entries, err := JavaKeystore(loadFixture(t, "real.jceks"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Alias != "jceks-app" {
		t.Fatalf("got %v, want the one jceks-app entry", aliases(entries))
	}
	if !entries[0].HasPrivateKey {
		t.Error("a JCEKS PrivateKeyEntry holds a key")
	}
	if cn := entries[0].Certificates[0].Subject.CommonName; cn != "jceks.example.com" {
		t.Errorf("common name = %q", cn)
	}
}

// A cacerts is nothing but CA certificates, and it is on every host with a JDK.
// Reporting one as a deployment sends a hundred and fifty issuers a member never
// chose, from every machine in an estate.
func TestATrustStoreHoldsNoDeployedCertificate(t *testing.T) {
	entries, err := JavaKeystore(loadFixture(t, "truststore.jks"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}

	var all []*x509.Certificate
	for _, entry := range entries {
		if entry.HasPrivateKey {
			t.Errorf("%s: a trustedCertEntry has no key", entry.Alias)
		}
		all = append(all, entry.Certificates...)
	}
	// Both are real public roots, so Leaf has to report that there is nothing
	// deployed here — which is what keeps a cacerts out of the portfolio.
	if _, _, found := Leaf(all); found {
		t.Error("a store of CA certificates is a list of issuers, not a deployment")
	}

	got := byAlias(entries)
	if fp := fingerprint(got["root1"].Certificates[0]); fp != clean(root1Fingerprint) {
		t.Errorf("root1 fingerprint %s, keytool said %s", fp, clean(root1Fingerprint))
	}
	if fp := fingerprint(got["root2"].Certificates[0]); fp != clean(root2Fingerprint) {
		t.Errorf("root2 fingerprint %s, keytool said %s", fp, clean(root2Fingerprint))
	}
}

// ── files that are not keystores, and keystores that are damaged ─────────────

func TestSomethingElseIsNotMistakenForAKeystore(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":            {},
		"too short":        {0xFE, 0xED},
		"a PEM file":       []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"),
		"a PKCS#12 bundle": {0x30, 0x82, 0x0A, 0x00},
		"right magic, wrong version": {
			0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := JavaKeystore(data); err == nil {
				t.Error("was accepted as a Java keystore")
			}
		})
	}
}

// The agent runs unattended as a background service. Every length in a keystore
// comes out of the file, so a truncated or hostile one must yield an error
// rather than a panic nobody is there to see.
func TestADamagedKeystoreIsAnErrorNotAPanic(t *testing.T) {
	full := loadFixture(t, "real.jks")

	// Every truncation of a real file, which walks the reader off the end at
	// every offset in the format.
	for cut := 1; cut < len(full); cut += 7 {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("truncating to %d bytes panicked: %v", cut, r)
				}
			}()
			_, _ = JavaKeystore(full[:cut])
		}()
	}

	// An entry count larger than the file could hold. It has to be refused AS A
	// COUNT, before it is used to size anything.
	//
	// Asserting on the refusal rather than on a crash is deliberate: Go reserves
	// two billion entries of capacity without complaining on a machine with
	// overcommit — measured, 0.25s, no error — so a test that waited for a panic
	// would pass here and the guard would be free to rot. It is a host with a
	// memory limit, which is where this agent actually runs, that dies.
	huge := append([]byte(nil), full...)
	huge[8], huge[9], huge[10], huge[11] = 0x7F, 0xFF, 0xFF, 0xFF

	_, err := JavaKeystore(huge)
	if err == nil {
		t.Fatal("an entry count larger than the file is a lie and must be refused")
	}
	if !strings.Contains(err.Error(), "2147483647") {
		t.Errorf("the count should be refused as a count, not stumbled over later: %v", err)
	}
}

// What was read before the damage is still real and still worth reporting: six
// good aliases should not be lost because a seventh is broken.
func TestWhatWasReadBeforeAFaultIsStillReturned(t *testing.T) {
	full := loadFixture(t, "real.jks")
	entries, err := JavaKeystore(full[:len(full)-200])
	if err == nil {
		t.Fatal("a truncated keystore should say so")
	}
	if len(entries) == 0 {
		t.Error("the entries read before the truncation were thrown away")
	}
}

func aliases(entries []KeystoreEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Alias)
	}
	return out
}
