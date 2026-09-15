package parse

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func leafPEM(t *testing.T, cn string) (string, *ecdsa.PrivateKey) {
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
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), key
}

func keyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func TestCertificatesFromPEM(t *testing.T) {
	certPEM, _ := leafPEM(t, "www.example.com")

	res, err := Certificates([]byte(certPEM))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Certificates) != 1 {
		t.Fatalf("want 1 certificate, got %d", len(res.Certificates))
	}
	if res.Certificates[0].Subject.CommonName != "www.example.com" {
		t.Errorf("wrong certificate: %s", res.Certificates[0].Subject.CommonName)
	}
	if res.HadPrivateKey {
		t.Error("a certificate-only file must not report a private key")
	}
}

// A combined key+certificate file is the haproxy layout and is common for nginx
// too. Refusing it outright would make those hosts report no certificates at
// all — the exact blindness this product exists to remove — so the certificate
// is extracted and the key is stepped over.
func TestCombinedKeyAndCertificateYieldsTheCertificate(t *testing.T) {
	certPEM, key := leafPEM(t, "haproxy.example.com")
	combined := keyPEM(t, key) + certPEM

	res, err := Certificates([]byte(combined))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Certificates) != 1 {
		t.Fatalf("want 1 certificate, got %d", len(res.Certificates))
	}
	if !res.HadPrivateKey {
		t.Error("the file held a key and that must be reported")
	}
}

// THE PROPERTY THE WHOLE AGENT RESTS ON. The output is re-encoded from parsed
// DER, never sliced out of the input, so no part of the key can survive into
// what is transmitted.
func TestEncodedOutputNeverCarriesTheKey(t *testing.T) {
	certPEM, key := leafPEM(t, "combined.example.com")
	combined := keyPEM(t, key) + certPEM

	res, err := Certificates([]byte(combined))
	if err != nil {
		t.Fatal(err)
	}
	encoded := EncodePEM(res.Certificates)

	if ContainsPrivateKey([]byte(encoded)) {
		t.Fatal("encoded output contains private key material")
	}
	if strings.Contains(encoded, "PRIVATE") {
		t.Fatal("encoded output mentions PRIVATE")
	}
}

func TestContainsPrivateKeyRecognisesTheForms(t *testing.T) {
	_, key := leafPEM(t, "x")
	cases := map[string]bool{
		keyPEM(t, key): true,
		"-----BEGIN RSA PRIVATE KEY-----\nrubbish\n-----END RSA PRIVATE KEY-----\n":             true,
		"-----BEGIN ENCRYPTED PRIVATE KEY-----\nrubbish\n-----END ENCRYPTED PRIVATE KEY-----\n": true,
		// Truncated: pem.Decode rejects it, but it is plainly still a key file
		// and the substring fallback is what catches it.
		"-----BEGIN PRIVATE KEY-----\nMIIEv": true,
		"just some text":                     false,
		"":                                   false,
	}
	for input, want := range cases {
		if got := ContainsPrivateKey([]byte(input)); got != want {
			t.Errorf("ContainsPrivateKey(%.40q) = %v, want %v", input, got, want)
		}
	}
}

func TestNonCertificateBytesAreNotAnError(t *testing.T) {
	if _, err := Certificates([]byte("# nginx config\nserver { }\n")); err == nil {
		t.Fatal("want ErrNoCertificates for a config file")
	}
}
