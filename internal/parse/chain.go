package parse

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"math/bits"
)

// Limits on the work one store can cost. A store is whatever one file, one
// keystore alias or one configured site holds, and every byte of it may have
// been written by somebody other than the machine's owner: a .pem dropped into
// a scanned directory, a keystore an application writes. Without these, one
// planted file of 325 end-entity certificates and 325 decoy CAs sharing a name
// cost five seconds of signature checks, and 2600 of each in one keystore alias
// cost five and a half MINUTES — during which a stop request went unanswered
// and every other source on the host went unscanned. Each limit is far above
// anything a real store needs; reaching one is reported, never silent.
const (
	// MaxCertificatesPerStore bounds what is indexed at all. The largest real
	// stores are trust bundles — /etc/ssl/certs/ca-certificates.crt holds
	// about 150 — and a 1 MiB file cannot hold more than about 650 ordinary
	// certificates anyway; keystores, read up to 8 MiB, are where this binds.
	MaxCertificatesPerStore = 4096

	// MaxLeavesPerStore bounds how many end-entity certificates one store
	// reports. A file of several sites' certificates is ordinary, and so is a
	// few generations of one site's kept side by side; hundreds of them in one
	// file is not a deployment anyone maintains by hand.
	MaxLeavesPerStore = 256

	// MaxChainDepth bounds one chain. Real chains are two to four certificates
	// above the leaf — five with a cross-signed root.
	MaxChainDepth = 10

	// VerifyBudget is how much signature checking one file may cost, in units
	// of one RSA-2048 verification (see verifyCost) — 40–60 µs on a current
	// x86 core, so the whole budget is about a quarter of a second whatever
	// keys a planted file chooses. A real store spends one check per leaf,
	// against the intermediate that issued it, plus a few for the chain above
	// that, shared by every leaf: MaxLeavesPerStore leaves under a P-384
	// intermediate (12 units each, the dearest in common use) still fit.
	VerifyBudget = 4096
)

// Budget is signature checking that several stores share: the aliases of one
// keystore, which are separate stores but one file somebody wrote. Without it a
// keystore split into a hundred aliases, each just inside its own limits, costs
// a hundred times what one may.
type Budget struct{ left int }

// NewBudget is a fresh VerifyBudget.
func NewBudget() *Budget { return &Budget{left: VerifyBudget} }

// LeafWithChain is one end-entity certificate and the certificates, from the
// same input, that actually issued it — nearest issuer first.
type LeafWithChain struct {
	Leaf  *x509.Certificate
	Chain []*x509.Certificate
}

// Shortfall says what a Store left undone. The zero value is a store that was
// read completely.
type Shortfall struct {
	// Truncated: the store held more than MaxCertificatesPerStore certificates
	// or more than MaxLeavesPerStore end-entity certificates, and the excess
	// was not reported. Certificates went unseen, so a caller must not let this
	// sweep mark anything absent.
	Truncated bool
	// OutOfBudget: the Budget ran out. Every leaf is still reported, but some
	// chains stop where the budget did, and a certificate whose issuance of
	// another could not be checked in time is reported as a leaf.
	OutOfBudget bool
	// Interrupted: the context was cancelled part-way. What came back is real,
	// and incomplete.
	Interrupted bool
}

// Add is both shortfalls at once: what several stores read from one file left
// undone between them.
func (s Shortfall) Add(other Shortfall) Shortfall {
	return Shortfall{
		Truncated:   s.Truncated || other.Truncated,
		OutOfBudget: s.OutOfBudget || other.OutOfBudget,
		Interrupted: s.Interrupted || other.Interrupted,
	}
}

// Store is one input's certificates, indexed once so that finding every leaf
// and every chain in it costs a bounded amount of work however hostile the
// input.
//
// THE COST WAS QUADRATIC, AND AN ATTACKER CHOSE THE CONSTANT. Each leaf's chain
// was found by trying every certificate in the input as its issuer, with a real
// signature check for every one whose name matched — and a name is free to
// copy. Here a certificate's possible issuers are looked up by name, every
// signature check is made at most once per (certificate, issuer) pair and
// shared by every leaf that reaches it, and the checks a store may make are
// budgeted. Reaching a limit is reported (Shortfall), so a caller can say the
// store was only partly read rather than seem to have read it all.
//
// Not safe for concurrent use.
type Store struct {
	ctx  context.Context
	all  []*x509.Certificate // the input, then the extra issuers; unique by DER
	ours int                 // all[:ours] is the input; the rest are extra issuers

	canonical map[string]*x509.Certificate   // DER → the one copy in all
	bySubject map[string][]*x509.Certificate // subject → possible issuers, in order

	checked map[pair]bool
	budget  *Budget
	short   Shortfall
}

type pair struct{ child, issuer *x509.Certificate }

// NewStore indexes what one store held — certs — together with any extra
// issuers the caller knows of from elsewhere (Apache's separate
// SSLCertificateChainFile, for one), which are candidates for a chain but never
// themselves reported as leaves. A certificate that appears twice is kept once.
// ctx is checked before every signature check, so cancelling it ends the work
// within one of them. budget may be shared with other stores read from the same
// file; nil is a fresh one.
func NewStore(ctx context.Context, budget *Budget, certs []*x509.Certificate, issuers ...*x509.Certificate) *Store {
	if budget == nil {
		budget = NewBudget()
	}
	s := &Store{
		ctx:       ctx,
		canonical: map[string]*x509.Certificate{},
		bySubject: map[string][]*x509.Certificate{},
		checked:   map[pair]bool{},
		budget:    budget,
	}
	add := func(cert *x509.Certificate) {
		if cert == nil || s.canonical[string(cert.Raw)] != nil {
			return
		}
		if len(s.all) == MaxCertificatesPerStore {
			s.short.Truncated = true
			return
		}
		s.canonical[string(cert.Raw)] = cert
		s.all = append(s.all, cert)
		if mayIssue(cert) {
			s.bySubject[string(cert.RawSubject)] = append(s.bySubject[string(cert.RawSubject)], cert)
		}
	}
	for _, cert := range certs {
		add(cert)
	}
	s.ours = len(s.all)
	for _, cert := range issuers {
		add(cert)
	}
	return s
}

// Shortfall reports what, if anything, this store's limits left undone.
func (s *Store) Shortfall() Shortfall { return s.short }

// Leaves finds every end-entity certificate in what a store held, each with its
// own chain — and returns none at all for a store of nothing but CA
// certificates.
//
// EVERY ONE, NOT THE FIRST. A .pem is a concatenation, and hosts concatenate
// more than chains: a file of several sites' certificates, or two generations
// of the same site's left side by side during a renewal, is ordinary. An
// earlier version picked the first end-entity certificate and sent everything
// else as its "chain", so every other site in the file was never reported as a
// certificate at all — and its expiry, which is the reason a member is paying
// for this, went unwatched. The server can filter a chain it is given; it
// cannot recover a certificate it was never sent.
//
// THE FIRST IS NOT EVEN THE RIGHT ONE, and that was the original reason this
// function exists. Order is not guaranteed — plenty of tools write the chain
// before the certificate it belongs to — and reporting an intermediate as the
// deployed certificate gives an operator the wrong expiry date for the thing
// that will actually break.
//
// AND A STORE MAY HOLD NO END-ENTITY CERTIFICATE AT ALL. That is what a TRUST
// STORE is — /etc/ssl/certs/ca-certificates.crt, a JDK cacerts, a chain file on
// its own — and they are everywhere. Treating one as a deployment reports a CA
// root nobody chose, carrying a hundred and twenty others as its "chain", from
// every host in an estate. So the result is empty for one, and the caller
// decides: a collector reading a file it merely came across skips it, and one
// reading a file a web server was CONFIGURED to serve reports the first
// certificate anyway (see ChainFor), because whatever is in there is what that
// site presents.
//
// A certificate that appears twice in the input is reported once. Each chain is
// built by ChainFor from the input plus the extra issuers, so a certificate
// that happens to share the file never rides along as somebody else's issuer.
func (s *Store) Leaves() []LeafWithChain {
	var out []LeafWithChain
	for _, cert := range s.all[:s.ours] {
		if s.ctx.Err() != nil {
			s.short.Interrupted = true
			break
		}
		if cert.IsCA {
			continue
		}
		if len(out) == MaxLeavesPerStore {
			s.short.Truncated = true
			break
		}
		out = append(out, LeafWithChain{Leaf: cert, Chain: s.ChainFor(cert)})
	}
	return out
}

// ChainFor walks upward from cert through the store, taking at each step the
// certificate that ISSUED the current one, and returns them leaf-side first. It
// stops at a self-signed certificate, at a missing link, on a cycle, at
// MaxChainDepth, or where the budget ran out. Nothing that did not sign its way
// into the chain is in it. cert need not be from the store.
//
// "Issued" is decided by the bytes, not by appearances: the candidate's subject
// must be byte-for-byte the current certificate's issuer, AND the current
// certificate's signature must verify under the candidate's key. A name alone
// is not enough — a re-keyed CA keeps its name, and so can anyone who mints a
// certificate — and a chain that claims an issuer which did not sign it hands
// the server a wrong answer about what this host trusts.
//
// Deliberately NOT x509's CheckSignatureFrom, which would also refuse a SHA-1
// signature and an issuer without a basicConstraints extension. Both are what
// an old chain file on an old host looks like, and this is an inventory of
// what is deployed, not a judgement on whether it should be: an operator needs
// to see the weak link to replace it. The one constraint kept is the one that
// says a certificate is NOT a CA — basicConstraints present with CA:FALSE — so
// a site certificate can never be filed as another one's issuer.
func (s *Store) ChainFor(cert *x509.Certificate) []*x509.Certificate {
	if c := s.canonical[string(cert.Raw)]; c != nil {
		cert = c
	}
	var chain []*x509.Certificate
	visited := map[*x509.Certificate]bool{cert: true}
	current := cert
	for len(chain) < MaxChainDepth && !s.selfSigned(current) {
		next := s.issuerOf(current, visited)
		if next == nil {
			break
		}
		visited[next] = true
		chain = append(chain, next)
		current = next
	}
	return chain
}

// issuerOf is the first candidate that signed cert (see ChainFor), or nil.
func (s *Store) issuerOf(cert *x509.Certificate, visited map[*x509.Certificate]bool) *x509.Certificate {
	for _, ca := range s.bySubject[string(cert.RawIssuer)] {
		if visited[ca] {
			continue // Itself, or a cycle.
		}
		if s.signed(cert, ca) {
			return ca
		}
	}
	return nil
}

func (s *Store) selfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer) && s.signed(cert, cert)
}

// signed reports whether issuer's key verifies child's signature, checking each
// pair at most once and charging the check to the store's budget. Once the
// budget is gone, or the context is cancelled, every unchecked pair reads as
// unsigned.
func (s *Store) signed(child, issuer *x509.Certificate) bool {
	key := pair{child, issuer}
	if ok, done := s.checked[key]; done {
		return ok
	}
	if s.short.OutOfBudget || s.short.Interrupted {
		return false
	}
	if s.ctx.Err() != nil {
		s.short.Interrupted = true
		return false
	}
	cost := verifyCost(issuer)
	if cost > s.budget.left {
		s.short.OutOfBudget = true
		return false
	}
	s.budget.left -= cost
	ok := issuer.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature) == nil
	s.checked[key] = ok
	return ok
}

// verifyCost is what checking a signature under this key costs, in RSA-2048
// verifications, so that a budget means time whatever key a planted CA
// chooses. Measured with Go 1.25 on x86-64, against RSA-2048 with e=65537 at
// 40–60 µs: RSA-4096 8×, RSA-8192 about 40×, RSA-16384 about 150×, P-256
// 2–3×, P-384 12×, P-521 55×, Ed25519 1.3–2×.
//
// RSA is charged by the cube of the modulus, which is what Go's constant-time
// arithmetic measured as (the textbook square under-charged RSA-8192 by half),
// and by the length of the exponent, which a key may set as high as 2³¹-1 for
// three times the work of the usual 65537. Nothing limits the modulus, so a
// key large enough to cost more than the whole budget is simply never checked.
func verifyCost(issuer *x509.Certificate) int {
	switch pub := issuer.PublicKey.(type) {
	case *rsa.PublicKey:
		k := (pub.N.BitLen() + 1023) / 1024
		modulus := max(1, k*k*k/8)
		// Square-and-multiply: one step per bit and one per set bit. 65537 is
		// 17 bits with 2 set.
		e := uint(max(pub.E, 0))
		exponent := (bits.Len(e) + bits.OnesCount(e) + 18) / 19
		return modulus * max(1, exponent)
	case *ecdsa.PublicKey:
		switch pub.Curve.Params().BitSize {
		case 256:
			return 3
		case 384:
			return 12
		default:
			return 60
		}
	case ed25519.PublicKey:
		return 2
	default:
		// Anything else CheckSignature refuses without doing the work.
		return 1
	}
}

// mayIssue is false only for a certificate that says it is NOT a CA:
// basicConstraints present with CA:FALSE. Absent basicConstraints is not a
// refusal — see ChainFor.
func mayIssue(cert *x509.Certificate) bool {
	return !cert.BasicConstraintsValid || cert.IsCA
}

// Leaves is Store.Leaves on a store of its own, for a caller with no use for
// the Shortfall.
func Leaves(ctx context.Context, certs []*x509.Certificate, issuers ...*x509.Certificate) []LeafWithChain {
	return NewStore(ctx, nil, certs, issuers...).Leaves()
}

// ChainFor is Store.ChainFor on a store of the candidates, for a caller with no
// use for the Shortfall: a chain cut short by the budget simply comes back
// shorter.
func ChainFor(ctx context.Context, cert *x509.Certificate, candidates []*x509.Certificate) []*x509.Certificate {
	return NewStore(ctx, nil, candidates).ChainFor(cert)
}
