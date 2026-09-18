package e2e

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// seedHost lays down the deliberately awkward mix the discovery plan calls for,
// and returns the root it wrote into.
//
// Each of these exists because it broke something, or because it is the shape
// that would hide a break:
//
//	valid.pem     an ordinary certificate with its key beside it
//	expired.pem   already expired — the finding a member most wants
//	ca-true.pem   SELF-SIGNED WITH basicConstraints CA:TRUE, which is what
//	              `openssl req -x509` produces by default. v0.2.0 filed these
//	              as trust anchors and reported nothing for them.
//	orphan.pem    a certificate with no key anywhere
//	bundle.p12    a PKCS#12 with an empty password
//	trust.pem     nothing but CA certificates and NO key — a trust store, which
//	              must NOT be reported, or every host uploads its issuer list
//	keystore.jks  keytool's own output, reachable through two overlapping roots
func seedHost(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mk := func(parts ...string) string {
		p := filepath.Join(append([]string{root}, parts...)...)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}

	now := time.Now()
	writeCert(t, mk("ssl", "valid.pem"), mk("ssl", "valid.key"), "valid.e2e.invalid", false, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	writeCert(t, mk("ssl", "expired.pem"), mk("ssl", "expired.key"), "expired.e2e.invalid", false, now.Add(-400*24*time.Hour), now.Add(-370*24*time.Hour))
	writeCert(t, mk("ssl", "ca-true.pem"), mk("ssl", "ca-true.key"), "selfsigned.e2e.invalid", true, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	writeCert(t, mk("ssl", "orphan.pem"), "", "orphan.e2e.invalid", false, now.Add(-time.Hour), now.Add(90*24*time.Hour))

	// A trust store: two CA certificates, no key. Must stay out of the report.
	var trust []byte
	for i := 0; i < 2; i++ {
		der, _ := makeCert(t, "Root CA "+string(rune('A'+i)), true, now.Add(-time.Hour), now.Add(3650*24*time.Hour))
		trust = append(trust, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if err := os.WriteFile(mk("ssl", "trust.pem"), trust, 0o644); err != nil {
		t.Fatal(err)
	}

	// A PKCS#12 with an empty password, which is the only one the agent tries.
	der, key := makeCert(t, "bundle.e2e.invalid", false, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pfx, err := pkcs12.Legacy.Encode(key, cert, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mk("ssl", "bundle.p12"), pfx, 0o644); err != nil {
		t.Fatal(err)
	}

	// keytool's own output — see internal/parse/testdata/README.md for why a
	// fixture this repository generated would prove nothing.
	jks, err := os.ReadFile(filepath.Join("..", "internal", "parse", "testdata", "real.jks"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mk("opt", "tomcat", "conf", "keystore.jks"), jks, 0o644); err != nil {
		t.Fatal(err)
	}

	// A web server configured to serve the valid certificate, with names the
	// listener probe would use as SNI.
	nginx := "http {\n    include " + filepath.ToSlash(mk("nginx", "sites-enabled", "site.conf")) + ";\n}\n"
	if err := os.WriteFile(mk("nginx", "nginx.conf"), []byte(nginx), 0o644); err != nil {
		t.Fatal(err)
	}
	site := "server {\n    listen 443 ssl;\n    server_name valid.e2e.invalid www.valid.e2e.invalid;\n" +
		"    ssl_certificate     " + filepath.ToSlash(mk("ssl", "valid.pem")) + ";\n" +
		"    ssl_certificate_key " + filepath.ToSlash(mk("ssl", "valid.key")) + ";\n}\n"
	if err := os.WriteFile(mk("nginx", "sites-enabled", "site.conf"), []byte(site), 0o644); err != nil {
		t.Fatal(err)
	}

	// A DIRECTORY OF NOTHING BUT PRIVATE KEYS, inside a scanned root, some of
	// them wearing a certificate's extension so the collector opens them.
	for _, name := range []string{"secret1.key", "secret2.pem", "secret3.pem"} {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		blob := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
		if err := os.WriteFile(mk("ssl", "keys", name), blob, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func makeCert(t *testing.T, cn string, isCA bool, from, to time.Time) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		NotBefore:             from,
		NotAfter:              to,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func writeCert(t *testing.T, certPath, keyPath, cn string, isCA bool, from, to time.Time) {
	t.Helper()
	der, key := makeCert(t, cn, isCA, from, to)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if keyPath == "" {
		return
	}
	blob := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, blob, 0o600); err != nil {
		t.Fatal(err)
	}
}

// patchConfig adds the roots that have no command-line flag. `--root` covers
// the filesystem collector; keystores and web-server configs are configured in
// the state file, which is exactly how a member with an unusual layout does it.
func patchConfig(t *testing.T, stateDir, hostRoot string) {
	t.Helper()
	path := filepath.Join(stateDir, "config.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["scan_roots"] = []string{filepath.Join(hostRoot, "ssl")}
	// TWO roots that reach the SAME keystore — the shape that was reported
	// twice in v0.2.1, and the reason this harness exists at all.
	cfg["keystore_roots"] = []string{
		filepath.Join(hostRoot, "opt", "tomcat", "conf"),
		filepath.Join(hostRoot, "opt", "*", "conf"),
	}
	cfg["nginx_configs"] = []string{filepath.Join(hostRoot, "nginx", "nginx.conf")}
	cfg["apache_configs"] = []string{}
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}
