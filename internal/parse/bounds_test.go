package parse

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// planted is the shape of the store that stalled a scan: leaves that all name
// one issuer, and decoy CAs that all carry that name and none of which signed
// them — so every (leaf, decoy) pair is a real signature check that fails, and
// the work is leaves × decoys. The issuer that DID sign them is not in the
// store.
func planted(t *testing.T, leaves, decoys int) []*x509.Certificate {
	t.Helper()
	absent := mint(t, "Collide CA", true, nil)
	var out []*x509.Certificate
	for i := 0; i < leaves; i++ {
		out = append(out, mint(t, fmt.Sprintf("leaf%d.example.com", i), false, &absent).cert)
	}
	for i := 0; i < decoys; i++ {
		out = append(out, mint(t, "Collide CA", true, nil).cert)
	}
	return out
}

// The finding: 325 leaves and 325 same-named decoys in one 661 KiB file cost
// five seconds, 2600 of each in one keystore alias five and a half minutes. The
// work is now bounded by the budget whatever the input — every leaf is still
// reported, and the store says it ran out rather than seeming complete.
func TestAPlantedStoreCostsNoMoreThanItsBudget(t *testing.T) {
	certs := planted(t, 120, 120) // 14,400 pairs at 3 units each: 10× the budget

	start := time.Now()
	store := NewStore(context.Background(), nil, certs)
	got := store.Leaves()
	t.Logf("%d leaves × %d decoys: %v, %d signature checks", 120, 120, time.Since(start), len(store.checked))

	if len(got) != 120 {
		t.Fatalf("got %d leaves, want all 120 — running out of budget must not drop a certificate", len(got))
	}
	for _, f := range got {
		if len(f.Chain) != 0 {
			t.Fatalf("%s has a chain of %v; no decoy signed it", f.Leaf.Subject.CommonName, names(f.Chain))
		}
	}
	if short := store.Shortfall(); !short.OutOfBudget || short.Truncated || short.Interrupted {
		t.Errorf("shortfall %+v, want OutOfBudget only", short)
	}
	if spent := VerifyBudget - store.budget.left; spent > VerifyBudget || len(store.checked) > VerifyBudget {
		t.Errorf("spent %d units over %d checks; the budget is %d", spent, len(store.checked), VerifyBudget)
	}
}

// What a real store costs: each leaf's signature is checked once against the
// intermediate that made it, and everything above that is checked once for all
// of them. This is what lets MaxLeavesPerStore leaves fit the budget.
func TestASharedChainIsCheckedOnceForEveryLeaf(t *testing.T) {
	root := mint(t, "Root", true, nil)
	inter := mint(t, "Intermediate", true, &root)
	certs := []*x509.Certificate{inter.cert, root.cert}
	const n = 200
	for i := 0; i < n; i++ {
		certs = append(certs, mint(t, fmt.Sprintf("site%d.example.com", i), false, &inter).cert)
	}

	store := NewStore(context.Background(), nil, certs)
	got := store.Leaves()
	if len(got) != n {
		t.Fatalf("got %d leaves, want %d", len(got), n)
	}
	for _, f := range got {
		sameChain(t, f.Leaf.Subject.CommonName, f.Chain, inter.cert, root.cert)
	}
	// One per leaf, intermediate-by-root, root-by-itself — plus each leaf's
	// own self-signed test, which costs nothing because its names differ.
	if len(store.checked) > n+2 {
		t.Errorf("%d signature checks for %d leaves sharing one chain; want at most %d", len(store.checked), n, n+2)
	}
	if short := store.Shortfall(); short != (Shortfall{}) {
		t.Errorf("a real bundle fell short: %+v", short)
	}
}

// The largest store the limits allow still resolves completely: the budget is
// sized for MaxLeavesPerStore leaves under a P-384 intermediate, the dearest
// key to verify under in common use.
func TestTheLeafLimitFitsTheBudget(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: "P-384 Intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	inter := issuer{cert: cert, key: key}
	if verifyCost(cert) != 12 {
		t.Fatalf("a P-384 key costs %d units; this test assumes 12", verifyCost(cert))
	}

	certs := []*x509.Certificate{inter.cert}
	for i := 0; i < MaxLeavesPerStore+1; i++ {
		certs = append(certs, mint(t, fmt.Sprintf("site%d.example.com", i), false, &inter).cert)
	}

	store := NewStore(context.Background(), nil, certs)
	got := store.Leaves()
	if len(got) != MaxLeavesPerStore {
		t.Fatalf("got %d leaves, want the limit, %d", len(got), MaxLeavesPerStore)
	}
	for _, f := range got {
		sameChain(t, f.Leaf.Subject.CommonName, f.Chain, inter.cert)
	}
	if short := store.Shortfall(); !short.Truncated || short.OutOfBudget {
		t.Errorf("shortfall %+v, want Truncated only — one leaf was left out, and every chain was resolved", short)
	}
}

func TestTheCertificateLimitIsReported(t *testing.T) {
	// Distinct certificates, cheaply: one key, a fresh serial each. Nothing is
	// verified, so who signed them does not matter.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certs := make([]*x509.Certificate, 0, MaxCertificatesPerStore+1)
	for i := 0; i < MaxCertificatesPerStore+1; i++ {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: "CA"},
			NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(der)
		certs = append(certs, cert)
	}
	store := NewStore(context.Background(), nil, certs)
	if len(store.all) != MaxCertificatesPerStore || !store.Shortfall().Truncated {
		t.Errorf("indexed %d of %d certificates, shortfall %+v", len(store.all), len(certs), store.Shortfall())
	}
}

// A chain longer than any real one stops at MaxChainDepth.
func TestAChainStopsAtTheDepthLimit(t *testing.T) {
	ca := mint(t, "CA 0", true, nil)
	certs := []*x509.Certificate{ca.cert}
	for i := 1; i <= MaxChainDepth+5; i++ {
		ca = mint(t, fmt.Sprintf("CA %d", i), true, &ca)
		certs = append(certs, ca.cert)
	}
	leaf := mint(t, "www.example.com", false, &ca)

	store := NewStore(context.Background(), nil, append(certs, leaf.cert))
	got := store.Leaves()
	if len(got) != 1 || len(got[0].Chain) != MaxChainDepth {
		t.Fatalf("got %d leaves, chain of %d; want 1 leaf with a chain of %d", len(got), len(got[0].Chain), MaxChainDepth)
	}
	if !store.Shortfall().TooDeep {
		t.Errorf("shortfall %+v, want TooDeep", store.Shortfall())
	}

	// Exactly MaxChainDepth is a whole chain, not a cut one.
	exact := NewStore(context.Background(), nil, append(certs[len(certs)-MaxChainDepth:], leaf.cert))
	if got := exact.Leaves(); len(got[0].Chain) != MaxChainDepth || exact.Shortfall().TooDeep {
		t.Errorf("a chain of exactly %d: got %d, shortfall %+v", MaxChainDepth, len(got[0].Chain), exact.Shortfall())
	}
}

// cancelAfter is a context whose Err turns non-nil after n calls, so a test can
// cancel at an exact point in the work rather than racing a timer.
type cancelAfter struct {
	context.Context
	n int
}

func (c *cancelAfter) Err() error {
	if c.n <= 0 {
		return context.Canceled
	}
	c.n--
	return nil
}

// A stop request was ignored for the whole of a planted file. The context is
// checked before every signature check, so cancelling ends the work within
// one of them, and the store says it was interrupted.
func TestCancellingStopsWithinOneSignatureCheck(t *testing.T) {
	certs := planted(t, 50, 50)

	ctx := &cancelAfter{Context: context.Background(), n: 10}
	store := NewStore(ctx, nil, certs)
	store.Leaves()
	if len(store.checked) > 10 {
		t.Errorf("%d signature checks after the context allowed 10", len(store.checked))
	}
	if !store.Shortfall().Interrupted {
		t.Errorf("shortfall %+v, want Interrupted", store.Shortfall())
	}
}

// The aliases of one keystore share one budget: a keystore split into many
// aliases, each inside its own limits, still costs no more than one file may.
func TestStoresSharingABudgetShareItsLimit(t *testing.T) {
	budget := NewBudget()
	first := NewStore(context.Background(), budget, planted(t, 120, 120))
	first.Leaves()
	if !first.Shortfall().OutOfBudget {
		t.Fatalf("the first store did not exhaust the budget: %+v", first.Shortfall())
	}

	second := NewStore(context.Background(), budget, planted(t, 2, 2))
	if got := second.Leaves(); len(got) != 2 {
		t.Fatalf("got %d leaves, want 2", len(got))
	}
	if len(second.checked) != 0 || !second.Shortfall().OutOfBudget {
		t.Errorf("the second store made %d checks on a spent budget; shortfall %+v", len(second.checked), second.Shortfall())
	}
}

// BenchmarkPlantedStore is the red team's measurement: N leaves and N decoy
// CAs, all RSA-2048 and all sharing one issuer name, in one store. Before the
// budget, 325 of each (a 661 KiB file) took 5 s and 2600 of each (one keystore
// alias) 5 m 35 s; the work now stops at VerifyBudget whatever N is.
//
//	go test -run '^$' -bench PlantedStore ./internal/parse
func BenchmarkPlantedStore(b *testing.B) {
	for _, n := range []int{325, 2600} {
		certs := plantedRSA(b, n)
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			for b.Loop() {
				store := NewStore(context.Background(), nil, certs)
				if got := store.Leaves(); len(got) != min(n, MaxLeavesPerStore) {
					b.Fatalf("got %d leaves", len(got))
				}
			}
		})
	}
}

// plantedRSA is planted with RSA-2048 keys, whose verification is the unit the
// budget is counted in. The decoys share one key so that making them is quick;
// distinct serials keep them distinct certificates.
func plantedRSA(b *testing.B, n int) []*x509.Certificate {
	b.Helper()
	collide := pkix.Name{CommonName: "Collide CA"}
	decoyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	parentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	parent := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: collide, IsCA: true, BasicConstraintsValid: true}
	var out []*x509.Certificate
	make1 := func(tmpl, signer *x509.Certificate, key *rsa.PrivateKey) {
		tmpl.SerialNumber = big.NewInt(serial.Add(1))
		tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &decoyKey.PublicKey, key)
		if err != nil {
			b.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(der)
		out = append(out, cert)
	}
	for i := 0; i < n; i++ {
		make1(&x509.Certificate{Subject: pkix.Name{CommonName: fmt.Sprintf("leaf%d", i)}, BasicConstraintsValid: true}, parent, parentKey)
	}
	for i := 0; i < n; i++ {
		decoy := &x509.Certificate{Subject: collide, IsCA: true, BasicConstraintsValid: true}
		make1(decoy, decoy, decoyKey)
	}
	return out
}
