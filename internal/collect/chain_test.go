package collect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SSLcom/dtp-discovery-agent/internal/parse"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// ── fixtures ─────────────────────────────────────────────────────────────────

// minted is a certificate together with the key that can sign under it.
type minted struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var mintSerial atomic.Int64

// mint makes a certificate named cn, signed by parent — or self-signed when
// parent is nil.
func mint(t *testing.T, cn string, isCA bool, parent *minted) minted {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(mintSerial.Add(1)),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.DNSNames = nil
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return minted{cert: cert, key: key}
}

func writePEM(t *testing.T, path string, certs ...*x509.Certificate) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(parse.EncodePEM(certs)), 0o644); err != nil {
		t.Fatal(err)
	}
}

// reported reads each observation back through the agent's own parser, as
// "leaf CN -> chain CNs", sorted — what DTP would receive, not what the fixture
// put in.
func reported(t *testing.T, res Result) []string {
	t.Helper()
	var out []string
	for _, o := range res.Observations {
		leaf, err := parse.Certificates([]byte(o.CertificatePEM))
		if err != nil || len(leaf.Certificates) != 1 {
			t.Fatalf("observation at %s does not carry exactly one certificate", o.Location)
		}
		var chain []string
		if o.ChainPEM != "" {
			parsed, err := parse.Certificates([]byte(o.ChainPEM))
			if err != nil {
				t.Fatalf("unparsable chain at %s: %v", o.Location, err)
			}
			for _, c := range parsed.Certificates {
				chain = append(chain, c.Subject.CommonName)
			}
		}
		out = append(out, leaf.Certificates[0].Subject.CommonName+" -> ["+strings.Join(chain, ", ")+"]")
	}
	sort.Strings(out)
	return out
}

func wantReported(t *testing.T, res Result, want ...string) {
	t.Helper()
	got := reported(t, res)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("reported:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// ── file ─────────────────────────────────────────────────────────────────────

// THE BUG: a .pem of several sites' certificates was one observation, with the
// other sites sent as its chain and never reported as certificates. Here two
// sites share an intermediate, a third came from somewhere else, and one of
// them was pasted in twice.
func TestAFileOfSeveralSitesIsSeveralCertificates(t *testing.T) {
	root := mint(t, "Root", true, nil)
	inter := mint(t, "Intermediate", true, &root)
	other := mint(t, "Other CA", true, nil)
	a := mint(t, "a.example.com", false, &inter)
	b := mint(t, "b.example.com", false, &inter)
	c := mint(t, "c.example.com", false, &other)

	dir := t.TempDir()
	path := filepath.Join(dir, "sites.pem")
	writePEM(t, path, a.cert, b.cert, inter.cert, c.cert, a.cert)

	res := collectIn(t, dir)
	wantReported(t, res,
		"a.example.com -> [Intermediate]",
		"b.example.com -> [Intermediate]",
		"c.example.com -> []",
	)
	for _, o := range res.Observations {
		if o.Location != path || o.Source != SourceFile {
			t.Errorf("observation at %s/%s, want the file itself", o.Source, o.Location)
		}
	}
}

// A root-first bundle is reported leaf to root.
func TestARootFirstBundleIsReportedLeafToRoot(t *testing.T) {
	root := mint(t, "Root", true, nil)
	inter := mint(t, "Intermediate", true, &root)
	leaf := mint(t, "www.example.com", false, &inter)

	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "fullchain.pem"), root.cert, inter.cert, leaf.cert)

	wantReported(t, collectIn(t, dir), "www.example.com -> [Intermediate, Root]")
}

// A file of only CA certificates WITH a key beside it is reported as it always
// was — its first certificate — but its chain holds only what issued that one.
func TestACABundleWithAKeyReportsItsFirstCertificateWithAFilteredChain(t *testing.T) {
	root := mint(t, "Root", true, nil)
	inter := mint(t, "Intermediate", true, &root)
	unrelated := mint(t, "Unrelated Root", true, nil)

	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "ca.pem"), inter.cert, unrelated.cert, root.cert)
	writeKey(t, filepath.Join(dir, "ca.key"))

	wantReported(t, collectIn(t, dir), "Intermediate -> [Root]")
}

// A file somebody planted under a scan root — leaves that all name one issuer
// and decoy CAs that all carry that name, none of which signed them — cost
// seconds per file before the budget, and stalled every source after it. Now
// it costs a bounded amount, every certificate in it is still reported, the
// shortfall is named, and the real site beside it is untouched.
func TestAPlantedFileIsBoundedAndTheSiteBesideItIsNot(t *testing.T) {
	absent := mint(t, "Collide CA", true, nil)
	var planted []*x509.Certificate
	for i := 0; i < 80; i++ {
		planted = append(planted, mint(t, fmt.Sprintf("leaf%d.example.com", i), false, &absent).cert)
	}
	for i := 0; i < 80; i++ {
		planted = append(planted, mint(t, "Collide CA", true, nil).cert)
	}
	inter := mint(t, "Intermediate", true, nil)
	site := mint(t, "www.example.com", false, &inter)

	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "planted.pem"), planted...)
	writePEM(t, filepath.Join(dir, "site.pem"), site.cert, inter.cert)

	res := collectIn(t, dir)
	got := reported(t, res)
	if len(got) != 81 {
		t.Fatalf("reported %d certificates, want 81 — every planted leaf and the site", len(got))
	}
	if !slices.Contains(got, "www.example.com -> [Intermediate]") {
		t.Errorf("the site beside the planted file lost its chain: %v", got)
	}
	if !res.Completed {
		t.Error("a chain cut short loses no certificate, so the sweep should stand")
	}
	if len(res.Errors) != 1 || res.Errors[0].Location != filepath.Join(dir, "planted.pem") ||
		!strings.Contains(res.Errors[0].Error, "possible issuers") {
		t.Errorf("errors %+v, want one naming the planted file", res.Errors)
	}
}

// More end-entity certificates than one store reports: the excess is unseen,
// so the sweep may not be used to mark anything absent, and the file is named.
func TestAFileOverTheLeafLimitSpoilsTheSweep(t *testing.T) {
	ca := mint(t, "CA", true, nil)
	var certs []*x509.Certificate
	for i := 0; i < parse.MaxLeavesPerStore+1; i++ {
		certs = append(certs, mint(t, fmt.Sprintf("site%d.example.com", i), false, &ca).cert)
	}
	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "many.pem"), certs...)

	res := collectIn(t, dir)
	if len(res.Observations) != parse.MaxLeavesPerStore {
		t.Errorf("reported %d, want the limit, %d", len(res.Observations), parse.MaxLeavesPerStore)
	}
	if res.Completed {
		t.Error("certificates went unreported, yet the sweep claims to be complete")
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0].Error, "were not examined") {
		t.Errorf("errors %+v, want one saying the rest were not examined", res.Errors)
	}
}

// ── server config ────────────────────────────────────────────────────────────

// Apache's SSLCertificateChainFile is a list of POSSIBLE issuers. A shared
// bundle of every intermediate on the host used to be appended to every site's
// chain wholesale.
func TestApacheChainFileContributesOnlyTheIssuersThatSigned(t *testing.T) {
	root := mint(t, "Root", true, nil)
	inter := mint(t, "Intermediate", true, &root)
	stray := mint(t, "Stray Intermediate", true, &root)
	leaf := mint(t, "www.example.com", false, &inter)

	dir := tree(t, map[string]string{
		"apache2.conf": `
<VirtualHost *:443>
    ServerName www.example.com
    SSLCertificateFile      {{root}}/ssl/site.pem
    SSLCertificateChainFile {{root}}/ssl/chain.pem
</VirtualHost>
`,
	})
	writePEM(t, filepath.Join(dir, "ssl/site.pem"), leaf.cert)
	writePEM(t, filepath.Join(dir, "ssl/chain.pem"), stray.cert, inter.cert, root.cert)

	wantReported(t, collectApache(t, dir, "apache2.conf"), "www.example.com -> [Intermediate, Root]")
}

// A configured file holding two sites' certificates reports only the one the
// server SERVES — the first — because a site binding is a deployment claim. The
// other is the file collector's to report, without a binding.
func TestAConfiguredFileOfTwoSitesReportsOnlyTheServedOne(t *testing.T) {
	inter := mint(t, "Intermediate", true, nil)
	a := mint(t, "a.example.com", false, &inter)
	b := mint(t, "b.example.com", false, nil)

	dir := tree(t, map[string]string{
		"nginx.conf": `
http {
    server {
        listen 443 ssl;
        server_name a.example.com;
        ssl_certificate {{root}}/ssl/both.pem;
    }
}
`,
	})
	writePEM(t, filepath.Join(dir, "ssl/both.pem"), a.cert, inter.cert, b.cert)

	res := collectNginx(t, dir, "nginx.conf")
	wantReported(t, res, "a.example.com -> [Intermediate]")
	if o := onlyObservation(t, res); o.Binding["server_name"] != "a.example.com" {
		t.Errorf("binding = %v", o.Binding)
	}
}

// A configured file can hold more candidates than a store keeps, but server
// config only ever reports the SERVED certificate — so the excess can shorten
// its chain and never hides a deployment. The source stays complete, or DTP
// would stop retiring this host's old placements over a long chain file.
func TestAnOversizedConfiguredFileShortensTheChainButKeepsTheSweepComplete(t *testing.T) {
	ca := mint(t, "CA", true, nil)
	certs := []*x509.Certificate{mint(t, "a.example.com", false, &ca).cert}
	for i := 0; i < parse.MaxCertificatesPerStore+1; i++ {
		certs = append(certs, mint(t, fmt.Sprintf("other%d.example.com", i), false, &ca).cert)
	}
	dir := tree(t, map[string]string{
		"nginx.conf": `
http {
    server {
        listen 443 ssl;
        server_name a.example.com;
        ssl_certificate {{root}}/ssl/big.pem;
    }
}
`,
	})
	writePEM(t, filepath.Join(dir, "ssl/big.pem"), certs...)

	res := collectNginx(t, dir, "nginx.conf")
	if o := onlyObservation(t, res); o.Binding["server_name"] != "a.example.com" {
		t.Errorf("binding = %v", o.Binding)
	}
	if !res.Completed {
		t.Error("only chain candidates were dropped, yet the sweep claims certificates went unseen")
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0].Error, "shorter chain") {
		t.Errorf("errors %+v, want one saying a chain was shortened", res.Errors)
	}
}

// ── java keystore ────────────────────────────────────────────────────────────

// A key entry holding only CA certificates is reported as its first one, with
// a chain walked AFTER Leaves — so a shortfall in that walk has to be taken
// then, not from the snapshot before it, or the cut chain goes up unnamed.
func TestAKeyEntrysFallbackChainShortfallIsNamed(t *testing.T) {
	cas := []minted{mint(t, "CA 0", true, nil)}
	for i := 1; i <= parse.MaxChainDepth+2; i++ {
		parent := cas[i-1]
		cas = append(cas, mint(t, fmt.Sprintf("CA %d", i), true, &parent))
	}
	bottom := cas[len(cas)-1]
	var rest []*x509.Certificate
	for i := len(cas) - 2; i >= 0; i-- {
		rest = append(rest, cas[i].cert)
	}
	p12, err := pkcs12.Modern.Encode(bottom.key, bottom.cert, rest, "")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.p12"), p12, 0o644); err != nil {
		t.Fatal(err)
	}

	res := collectKeystores(t, dir)
	if len(res.Observations) != 1 {
		t.Fatalf("reported %d observations, want the key entry's own certificate", len(res.Observations))
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0].Error, "chain deeper") {
		t.Errorf("errors %+v, want one naming the shortened chain", res.Errors)
	}
}


// A PKCS#12 keystore whose CA list carries another site's certificate and an
// intermediate that did not issue this one.
func TestAKeystoreEntryReportsEachLeafWithItsOwnChain(t *testing.T) {
	root := mint(t, "Root", true, nil)
	inter := mint(t, "Intermediate", true, &root)
	stray := mint(t, "Stray Intermediate", true, &root)
	leaf := mint(t, "www.example.com", false, &inter)
	other := mint(t, "other.example.com", false, &stray)

	p12, err := pkcs12.Modern.Encode(leaf.key, leaf.cert, []*x509.Certificate{root.cert, other.cert, inter.cert}, "")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tomcat.p12"), p12, 0o644); err != nil {
		t.Fatal(err)
	}

	wantReported(t, collectKeystores(t, dir),
		"www.example.com -> [Intermediate, Root]",
		"other.example.com -> []",
	)
}

// ── listener ─────────────────────────────────────────────────────────────────

// A server misconfigured to send a stray certificate in its handshake. The
// presented leaf is still the observation; the stray is not its chain.
func TestAListenerSendingAStrayCertificateDoesNotPolluteTheChain(t *testing.T) {
	root := mint(t, "Root", true, nil)
	inter := mint(t, "Intermediate", true, &root)
	leaf := mint(t, "served.example.com", false, &inter)
	stray := mint(t, "stray.example.com", false, nil)

	port := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{leaf.cert.Raw, stray.cert.Raw, inter.cert.Raw},
		PrivateKey:  leaf.key,
	}}})

	wantReported(t, collectPorts(t, ListenerBounds{}, port), "served.example.com -> [Intermediate]")
}

// Nothing above is allowed to change what reaches the wire: a certificate is
// still constructed from parsed DER, so a key in the same file never rides
// along whichever certificate it is attached to.
func TestSeveralLeavesBesideAKeyCarryNoKeyMaterial(t *testing.T) {
	a := mint(t, "a.example.com", false, nil)
	b := mint(t, "b.example.com", false, nil)
	keyDER, err := x509.MarshalECPrivateKey(a.key)
	if err != nil {
		t.Fatal(err)
	}
	blob := parse.EncodePEM([]*x509.Certificate{a.cert}) +
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})) +
		parse.EncodePEM([]*x509.Certificate{b.cert})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "combined.pem"), []byte(blob), 0o600); err != nil {
		t.Fatal(err)
	}
	res := collectIn(t, dir)
	wantReported(t, res, "a.example.com -> []", "b.example.com -> []")
	for _, o := range res.Observations {
		if parse.ContainsPrivateKey([]byte(o.CertificatePEM + o.ChainPEM)) {
			t.Fatal("key material in an observation")
		}
		if !o.PrivateKeyPresent {
			t.Error("the key in the file was not flagged")
		}
	}
}
