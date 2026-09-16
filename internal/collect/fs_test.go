package collect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SSLcom/dtp-discovery-agent/internal/parse"
)

func writeLeaf(t *testing.T, path, cn string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeKey(t *testing.T, path string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func collectIn(t *testing.T, root string) Result {
	t.Helper()
	c := &FS{Bounds: Bounds{Roots: []string{root}}}
	return c.Collect(context.Background())
}

func TestFindsACertificateAndItsSiblingKeyWithoutReadingIt(t *testing.T) {
	dir := t.TempDir()
	writeLeaf(t, filepath.Join(dir, "site.pem"), "www.example.com")
	writeKey(t, filepath.Join(dir, "site.key"))

	res := collectIn(t, dir)

	if len(res.Observations) != 1 {
		t.Fatalf("want 1 observation, got %d", len(res.Observations))
	}
	obs := res.Observations[0]
	if !obs.PrivateKeyPresent {
		t.Error("the sibling key must be reported as present")
	}
	if !strings.HasSuffix(obs.PrivateKeyLocation, "site.key") {
		t.Errorf("key location = %q", obs.PrivateKeyLocation)
	}
	// THE POINT: its path, never its contents.
	if strings.Contains(obs.CertificatePEM, "PRIVATE") || strings.Contains(obs.ChainPEM, "PRIVATE") {
		t.Fatal("key material leaked into the observation")
	}
	if !res.Completed {
		t.Error("a clean sweep must report Completed")
	}
}

func TestFindsLetsEncryptLayout(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live", "example.com")
	writeLeaf(t, filepath.Join(live, "fullchain.pem"), "example.com")
	writeKey(t, filepath.Join(live, "privkey.pem"))

	res := collectIn(t, dir)

	if len(res.Observations) != 1 {
		t.Fatalf("want 1 observation, got %d", len(res.Observations))
	}
	if !strings.HasSuffix(res.Observations[0].PrivateKeyLocation, "privkey.pem") {
		t.Errorf("did not pair fullchain.pem with privkey.pem: %q", res.Observations[0].PrivateKeyLocation)
	}
}

// A file that is not a certificate is not an error — a host is full of them,
// and reporting each as a collector failure would make every run look broken
// AND stop absence detection working.
func TestNonCertificateFilesAreSilentlySkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "nginx.pem"), []byte("server { listen 443; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res := collectIn(t, dir)

	if len(res.Observations) != 0 || len(res.Errors) != 0 {
		t.Fatalf("observations=%d errors=%d, want none of either", len(res.Observations), len(res.Errors))
	}
	if !res.Completed {
		t.Error("skipping a non-certificate file must not mark the sweep incomplete")
	}
}

// A root that does not exist on this host is not a failure. Most hosts have
// neither /etc/apache2 nor /etc/httpd, and treating the absent one as an error
// would mark every sweep incomplete — which would in turn stop DTP ever
// concluding a certificate had been removed.
func TestAnAbsentRootIsNotAFailure(t *testing.T) {
	res := collectIn(t, filepath.Join(t.TempDir(), "definitely-not-here"))

	if len(res.Errors) != 0 {
		t.Errorf("want no errors, got %v", res.Errors)
	}
	if !res.Completed {
		t.Error("an absent root must leave the sweep complete")
	}
}

func TestOversizedFilesAreNotRead(t *testing.T) {
	dir := t.TempDir()
	writeLeaf(t, filepath.Join(dir, "big.pem"), "big.example.com")

	c := &FS{Bounds: Bounds{Roots: []string{dir}, MaxFileBytes: 16}}
	res := c.Collect(context.Background())

	if len(res.Observations) != 0 {
		t.Fatal("a file past the size bound must not be opened")
	}
}

func TestDepthIsBounded(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "a", "b", "c", "d", "e")
	writeLeaf(t, filepath.Join(deep, "deep.pem"), "deep.example.com")

	c := &FS{Bounds: Bounds{Roots: []string{dir}, MaxDepth: 2}}
	res := c.Collect(context.Background())

	if len(res.Observations) != 0 {
		t.Fatalf("walked past the depth bound: %d observations", len(res.Observations))
	}
}

// A certificate and its key in ONE file (the haproxy layout). The certificate is
// still reported; the key is recorded as living in that same path.
func TestCombinedFileReportsTheCertificateAndFlagsTheKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "combined.pem")

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "haproxy.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)

	combined := append(
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...)
	if err := os.WriteFile(path, combined, 0o600); err != nil {
		t.Fatal(err)
	}

	res := collectIn(t, dir)

	if len(res.Observations) != 1 {
		t.Fatalf("want 1 observation, got %d", len(res.Observations))
	}
	obs := res.Observations[0]
	if obs.PrivateKeyLocation != path {
		t.Errorf("key location = %q, want the combined file itself", obs.PrivateKeyLocation)
	}
	if strings.Contains(obs.CertificatePEM, "PRIVATE") {
		t.Fatal("key material leaked into the observation")
	}
}

// The mode is reported so a member can see that a key beside a certificate is
// world-readable. `Perm().String()` is ls-style text ("-rw-r--r--"), not octal,
// so the obvious-looking formatting produced "0rw-r--r--" — a value that is not
// a mode at all and that no one reading the portfolio could act on.
func TestFileModeIsReportedAsOctal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "site.pem")
	writeLeaf(t, path, "mode.example.com")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	res := collectIn(t, dir)
	if len(res.Observations) != 1 {
		t.Fatalf("want 1 observation, got %d", len(res.Observations))
	}
	if got := res.Observations[0].FileMode; got != "0644" {
		t.Errorf("file mode = %q, want %q", got, "0644")
	}
}

func TestFileModeReportsATightenedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tight.pem")
	writeLeaf(t, path, "tight.example.com")
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}

	res := collectIn(t, dir)
	if len(res.Observations) != 1 {
		t.Fatalf("want 1 observation, got %d", len(res.Observations))
	}
	if got := res.Observations[0].FileMode; got != "0600" {
		t.Errorf("file mode = %q, want %q", got, "0600")
	}
}

// A file of nothing but CA certificates is a TRUST STORE, not a deployment —
// and the directories this collector walks are full of them. Measured on an
// ordinary host: /etc/ssl/certs/ca-certificates.crt was reported as one CA root
// nobody chose, carrying a hundred and twenty others as its "chain". Times every
// machine in an estate, that buries the certificates a member is paying to keep
// track of under the list of issuers their distribution happens to ship.
func TestATrustBundleIsNotReportedAsADeployment(t *testing.T) {
	dir := t.TempDir()
	writeCABundle(t, filepath.Join(dir, "ca-certificates.crt"), 3)
	writeLeaf(t, filepath.Join(dir, "site.pem"), "www.example.com")

	res := collectIn(t, dir)

	if len(res.Observations) != 1 {
		var got []string
		for _, o := range res.Observations {
			got = append(got, o.Location)
		}
		t.Fatalf("got %v, want only the real certificate", got)
	}
	if !strings.HasSuffix(res.Observations[0].Location, "site.pem") {
		t.Errorf("reported %q rather than the deployed certificate", res.Observations[0].Location)
	}
	// Silently: a trust bundle is on every host, so an error here would be an
	// error everywhere, and a sweep that never completes never retires anything.
	if len(res.Errors) != 0 || !res.Completed {
		t.Errorf("reading a trust bundle is not a fault: %v (completed %v)", res.Errors, res.Completed)
	}
}

// The other half of the same rule: a bundle is a concatenation and plenty of
// tools write the chain first. Reporting an intermediate as the deployed
// certificate gives an operator the wrong expiry for the thing that will break.
func TestTheEndEntityCertificateIsFoundWhereverItSitsInTheFile(t *testing.T) {
	dir := t.TempDir()
	writeChainThenLeaf(t, filepath.Join(dir, "bundle.pem"), "www.example.com")

	res := collectIn(t, dir)
	if len(res.Observations) != 1 {
		t.Fatalf("got %d observations, want 1 (errors %v)", len(res.Observations), res.Errors)
	}
	parsed, err := parse.Certificates([]byte(res.Observations[0].CertificatePEM))
	if err != nil || len(parsed.Certificates) != 1 {
		t.Fatalf("observation did not carry one certificate: %v", err)
	}
	if cn := parsed.Certificates[0].Subject.CommonName; cn != "www.example.com" {
		t.Errorf("reported %q as the deployed certificate; the leaf is www.example.com", cn)
	}
}

// writeCABundle writes a file of nothing but CA certificates, as a distribution
// trust store is.
func writeCABundle(t *testing.T, path string, count int) {
	t.Helper()
	var out []byte
	for i := 0; i < count; i++ {
		out = append(out, pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: makeCert(t, fmt.Sprintf("Root CA %d", i), true),
		})...)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeChainThenLeaf writes the issuer before the certificate it issued, which
// is a layout real tools produce.
func writeChainThenLeaf(t *testing.T, path, cn string) {
	t.Helper()
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: makeCert(t, "Issuing CA", true)})
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: makeCert(t, cn, false)})...)
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func makeCert(t *testing.T, cn string, isCA bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
