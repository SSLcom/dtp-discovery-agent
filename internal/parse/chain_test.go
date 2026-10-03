package parse

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync/atomic"
	"testing"
	"time"
)

// issuer is a certificate together with the key that can sign under it.
type issuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial atomic.Int64

// mint makes a certificate named cn, signed by parent — or self-signed when
// parent is nil.
func mint(t *testing.T, cn string, isCA bool, parent *issuer) issuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial.Add(1)),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
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
	return issuer{cert: cert, key: key}
}

func names(certs []*x509.Certificate) []string {
	out := make([]string, 0, len(certs))
	for _, c := range certs {
		out = append(out, c.Subject.CommonName)
	}
	return out
}

func sameChain(t *testing.T, what string, got []*x509.Certificate, want ...*x509.Certificate) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: chain %v, want %v", what, names(got), names(want))
		return
	}
	for i := range want {
		if !got[i].Equal(want[i]) {
			t.Errorf("%s: chain %v, want %v (position %d is a different certificate)", what, names(got), names(want), i)
			return
		}
	}
}

// The bug this exists for: a file of several sites' certificates was ONE
// observation, the others sent as its "chain" and never reported as
// certificates. Here three sites share an intermediate that signed two of them;
// the third was issued elsewhere, so the intermediate is not its chain.
func TestEveryLeafInAFileIsReportedWithOnlyItsOwnIssuers(t *testing.T) {
	root := mint(t, "Root", true, nil)
	inter := mint(t, "Intermediate", true, &root)
	other := mint(t, "Other CA", true, nil)
	a := mint(t, "a.example.com", false, &inter)
	b := mint(t, "b.example.com", false, &inter)
	c := mint(t, "c.example.com", false, &other)

	got := Leaves(context.Background(), []*x509.Certificate{a.cert, b.cert, c.cert, inter.cert})
	if len(got) != 3 {
		t.Fatalf("got %d leaves, want 3", len(got))
	}
	for i, want := range []*x509.Certificate{a.cert, b.cert, c.cert} {
		if !got[i].Leaf.Equal(want) {
			t.Errorf("leaf %d is %s, want %s", i, got[i].Leaf.Subject.CommonName, want.Subject.CommonName)
		}
	}
	sameChain(t, "a", got[0].Chain, inter.cert)
	sameChain(t, "b", got[1].Chain, inter.cert)
	sameChain(t, "c (issued by a CA not in the file)", got[2].Chain)
}

// Bundles are often written root first. The chain is reported leaf to root
// whatever order the file used.
func TestARootFirstBundleIsReportedLeafToRoot(t *testing.T) {
	root := mint(t, "Root", true, nil)
	inter := mint(t, "Intermediate", true, &root)
	leaf := mint(t, "www.example.com", false, &inter)

	got := Leaves(context.Background(), []*x509.Certificate{root.cert, inter.cert, leaf.cert})
	if len(got) != 1 {
		t.Fatalf("got %d leaves, want 1", len(got))
	}
	sameChain(t, "root-first", got[0].Chain, inter.cert, root.cert)
}

// A name is not issuance. A CA re-keyed under the same name — or anyone who
// mints a certificate with that subject — did not sign this leaf, and must not
// be reported as its issuer.
func TestASameNamedCAWithADifferentKeyIsNotTheIssuer(t *testing.T) {
	real := mint(t, "Issuing CA", true, nil)
	impostor := mint(t, "Issuing CA", true, nil)
	leaf := mint(t, "www.example.com", false, &real)

	got := Leaves(context.Background(), []*x509.Certificate{leaf.cert, impostor.cert})
	if len(got) != 1 {
		t.Fatalf("got %d leaves, want 1", len(got))
	}
	sameChain(t, "impostor only", got[0].Chain)

	// And with both present, the one that signed it is chosen whichever comes
	// first.
	got = Leaves(context.Background(), []*x509.Certificate{leaf.cert, impostor.cert, real.cert})
	sameChain(t, "both present", got[0].Chain, real.cert)
}

func TestALeafWithNoIssuerPresentHasAnEmptyChain(t *testing.T) {
	ca := mint(t, "Absent CA", true, nil)
	leaf := mint(t, "www.example.com", false, &ca)

	got := Leaves(context.Background(), []*x509.Certificate{leaf.cert})
	if len(got) != 1 {
		t.Fatalf("got %d leaves, want 1", len(got))
	}
	sameChain(t, "lone leaf", got[0].Chain)
}

// A trust store is not a deployment: no leaves at all, and the caller decides.
// ChainFor is what a caller that reports the first certificate anyway uses, and
// a self-signed root has no chain however many others share the file.
func TestAFileOfOnlyCACertificatesHasNoLeaves(t *testing.T) {
	root := mint(t, "Root", true, nil)
	inter := mint(t, "Intermediate", true, &root)
	unrelated := mint(t, "Unrelated Root", true, nil)
	all := []*x509.Certificate{inter.cert, unrelated.cert, root.cert}

	if got := Leaves(context.Background(), all); len(got) != 0 {
		t.Fatalf("a store of CA certificates yielded %d leaves", len(got))
	}
	sameChain(t, "first of a CA bundle", ChainFor(context.Background(), all[0], all), root.cert)
	sameChain(t, "self-signed root", ChainFor(context.Background(), unrelated.cert, all))
}

func TestADuplicatedLeafIsReportedOnce(t *testing.T) {
	ca := mint(t, "Issuing CA", true, nil)
	leaf := mint(t, "www.example.com", false, &ca)

	got := Leaves(context.Background(), []*x509.Certificate{leaf.cert, ca.cert, leaf.cert, ca.cert})
	if len(got) != 1 {
		t.Fatalf("got %d leaves, want 1", len(got))
	}
	sameChain(t, "duplicated", got[0].Chain, ca.cert)
}

// A site certificate is never another one's issuer, even when its name and key
// would fit: basicConstraints CA:FALSE says its key may not sign certificates.
func TestALeafIsNeverFiledAsAnIssuer(t *testing.T) {
	notACA := mint(t, "Issuing CA", false, nil)
	// Signed with the non-CA's key directly, which x509.CreateCertificate
	// permits — the point is what the reader concludes.
	leaf := mint(t, "www.example.com", false, &notACA)

	got := Leaves(context.Background(), []*x509.Certificate{leaf.cert, notACA.cert})
	if len(got) != 2 {
		t.Fatalf("got %d leaves, want 2", len(got))
	}
	sameChain(t, "signed by a non-CA", got[0].Chain)
}

// Issuers the caller knows of from elsewhere — Apache's SSLCertificateChainFile
// — are candidates, never automatically chain.
func TestExtraIssuersAreCandidatesNotChain(t *testing.T) {
	root := mint(t, "Root", true, nil)
	inter := mint(t, "Intermediate", true, &root)
	stray := mint(t, "Stray Intermediate", true, &root)
	leaf := mint(t, "www.example.com", false, &inter)

	got := Leaves(context.Background(), []*x509.Certificate{leaf.cert}, stray.cert, root.cert, inter.cert)
	if len(got) != 1 {
		t.Fatalf("got %d leaves, want 1 — an extra issuer is never itself a leaf", len(got))
	}
	sameChain(t, "with a chain file", got[0].Chain, inter.cert, root.cert)
}

// Two CAs that cross-sign each other must not loop forever.
func TestACrossSigningCycleTerminates(t *testing.T) {
	keyA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyB, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nameA, nameB := pkix.Name{CommonName: "CA A"}, pkix.Name{CommonName: "CA B"}
	tmpl := func(name pkix.Name) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(serial.Add(1)), Subject: name,
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true,
		}
	}
	parse := func(der []byte, err error) *x509.Certificate {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	aByB := parse(x509.CreateCertificate(rand.Reader, tmpl(nameA), tmpl(nameB), &keyA.PublicKey, keyB))
	bByA := parse(x509.CreateCertificate(rand.Reader, tmpl(nameB), tmpl(nameA), &keyB.PublicKey, keyA))
	leaf := mint(t, "www.example.com", false, &issuer{cert: aByB, key: keyA})

	got := Leaves(context.Background(), []*x509.Certificate{leaf.cert, aByB, bByA})
	if len(got) != 1 {
		t.Fatalf("got %d leaves, want 1", len(got))
	}
	sameChain(t, "cycle", got[0].Chain, aByB, bByA)
}

// mintAs signs tmpl with key, under parent (or itself when parent is nil), so a
// test can choose what mint does not: validity dates, an absent
// basicConstraints, and a key shared between two certificates.
func mintAs(t *testing.T, tmpl *x509.Certificate, key *ecdsa.PrivateKey, parent *issuer) issuer {
	t.Helper()
	tmpl.SerialNumber = big.NewInt(serial.Add(1))
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
	return issuer{cert: cert, key: key}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// One CA key under two certificates — self-signed, and cross-signed by an older
// root — is how a CA bootstraps trust, and a bundle often carries both. Taking
// whichever came first reported the 2021 Let's Encrypt chain through the
// EXPIRED DST Root CA X3 cross-sign while the valid self-signed ISRG Root X1
// sat beside it. The order of preference — valid now, then self-signed, then
// position — is the server's (DTP::Crypto::CertificateInput).
func TestTheBestOfSeveralIssuersIsChosen(t *testing.T) {
	now := time.Now()
	valid := func(name string) *x509.Certificate {
		return &x509.Certificate{
			Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true,
		}
	}
	expired := func(name string) *x509.Certificate {
		tmpl := valid(name)
		tmpl.NotBefore, tmpl.NotAfter = now.Add(-48*time.Hour), now.Add(-24*time.Hour)
		return tmpl
	}

	oldRoot := mintAs(t, valid("DST Root CA X3"), newKey(t), nil)
	rootKey := newKey(t)
	selfSigned := mintAs(t, valid("ISRG Root X1"), rootKey, nil)
	crossSigned := mintAs(t, expired("ISRG Root X1"), rootKey, &oldRoot)
	validCross := mintAs(t, valid("ISRG Root X1"), rootKey, &oldRoot)
	otherRoot := mintAs(t, valid("Another Old Root"), newKey(t), nil)
	otherCross := mintAs(t, valid("ISRG Root X1"), rootKey, &otherRoot)
	expiredSelf := mintAs(t, expired("ISRG Root X1"), rootKey, nil)
	inter := mint(t, "R3", true, &selfSigned)
	leaf := mint(t, "www.example.com", false, &inter)

	for _, tc := range []struct {
		name  string
		roots []*x509.Certificate
		want  []*x509.Certificate
	}{
		{"an expired cross-sign listed first", []*x509.Certificate{crossSigned.cert, oldRoot.cert, selfSigned.cert},
			[]*x509.Certificate{inter.cert, selfSigned.cert}},
		{"both valid: the self-signed root", []*x509.Certificate{validCross.cert, oldRoot.cert, selfSigned.cert},
			[]*x509.Certificate{inter.cert, selfSigned.cert}},
		{"validity outranks being self-signed", []*x509.Certificate{expiredSelf.cert, validCross.cert, oldRoot.cert},
			[]*x509.Certificate{inter.cert, validCross.cert, oldRoot.cert}},
		{"otherwise the first", []*x509.Certificate{otherCross.cert, validCross.cert, oldRoot.cert, otherRoot.cert},
			[]*x509.Certificate{inter.cert, otherCross.cert, otherRoot.cert}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Leaves(context.Background(), append([]*x509.Certificate{leaf.cert, inter.cert}, tc.roots...))
			if len(got) != 1 {
				t.Fatalf("got %d leaves, want 1", len(got))
			}
			sameChain(t, tc.name, got[0].Chain, tc.want...)
		})
	}
}

// A certificate with no basicConstraints looks like an end-entity certificate
// to x509 — a v1 root has no extensions at all, and legacy private PKIs run
// intermediates without one — so a chain file of either was reported as a
// site. One shown to have issued another certificate in the same store is not
// a leaf. One that issued nothing there stays a leaf, as the server has it: the
// bytes cannot say otherwise.
func TestACertificateThatIssuedAnotherIsNotALeaf(t *testing.T) {
	now := time.Now()
	noConstraints := func(name string) *x509.Certificate {
		return &x509.Certificate{Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	}
	legacyRoot := mintAs(t, noConstraints("Legacy Root"), newKey(t), nil)
	legacyInter := mintAs(t, noConstraints("Legacy Intermediate"), newKey(t), &legacyRoot)
	leaf := mint(t, "www.example.com", false, &legacyInter)
	if legacyRoot.cert.BasicConstraintsValid || legacyInter.cert.IsCA {
		t.Fatal("the fixture has basicConstraints; this test needs none")
	}

	store := NewStore(context.Background(), nil, []*x509.Certificate{legacyRoot.cert, legacyInter.cert, leaf.cert})
	got := store.Leaves()
	if len(got) != 1 || !got[0].Leaf.Equal(leaf.cert) {
		t.Fatalf("leaves %v, want only www.example.com", func() (n []string) {
			for _, f := range got {
				n = append(n, f.Leaf.Subject.CommonName)
			}
			return
		}())
	}
	sameChain(t, "legacy chain", got[0].Chain, legacyInter.cert, legacyRoot.cert)

	// Shipped alone, nothing shows it issued anything.
	if got := Leaves(context.Background(), []*x509.Certificate{legacyRoot.cert}); len(got) != 1 {
		t.Errorf("a lone root without basicConstraints: %d leaves, want 1", len(got))
	}

	// An explicit CA:FALSE is never overruled, whatever its key signed.
	notACA := mint(t, "Not A CA", false, nil)
	signedAnyway := mint(t, "signed.example.com", false, &notACA)
	if got := Leaves(context.Background(), []*x509.Certificate{notACA.cert, signedAnyway.cert}); len(got) != 2 {
		t.Errorf("CA:FALSE that signed something: %d leaves, want 2", len(got))
	}
}
