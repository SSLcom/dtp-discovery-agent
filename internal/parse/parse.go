// Package parse turns bytes found on a host into certificates — and only into
// certificates.
//
// THE STRUCTURAL GUARANTEE OF THIS PACKAGE: nothing it returns is a copy of its
// input. Certificates are parsed to x509.Certificate and re-encoded from
// cert.Raw, so the PEM the agent transmits is CONSTRUCTED from DER the parser
// understood, never sliced out of the file. There is therefore no path by which
// a private key sitting in the same file can ride along, whatever a collector
// does afterwards.
package parse

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// PEM block types that are private key material. Matched by SUFFIX so the
// algorithm-specific forms ("RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED
// PRIVATE KEY") are all covered without listing every algorithm that will ever
// exist.
const privateKeySuffix = "PRIVATE KEY"

// ErrNoCertificates means these bytes are not a certificate store the agent
// understands — a config file, a CRL, a text file someone named ".pem".
var ErrNoCertificates = errors.New("no certificates found")

// ContainsPrivateKey reports whether these bytes hold private key material.
//
// Used to record THAT a key sits beside (or inside) a certificate file, and as
// the outbound guard's test in package transport. Deliberately broad: it falls
// back to a substring match so that a truncated or slightly malformed key —
// which pem.Decode rejects — is still recognised for what it is. A false
// positive costs one unreported key location; a false negative could cost a
// customer their key.
func ContainsPrivateKey(data []byte) bool {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if strings.HasSuffix(strings.ToUpper(block.Type), privateKeySuffix) {
			return true
		}
	}
	return bytes.Contains(bytes.ToUpper(data), []byte(privateKeySuffix))
}

// Result is what a file turned out to hold.
type Result struct {
	Certificates []*x509.Certificate
	// Whether private key material shared the file. Reported to DTP as a
	// boolean and a path — an operator needs to know a key exists and what mode
	// it is — while the bytes themselves are discarded here.
	HadPrivateKey bool
}

// Certificates extracts every X.509 certificate from PEM or DER bytes.
//
// A combined key+certificate file is NOT refused. That layout is standard —
// haproxy requires it, and plenty of hosts do it for nginx too — so refusing it
// would make those machines report no certificates at all, which is the failure
// this whole product exists to prevent. Only CERTIFICATE blocks are parsed; the
// key blocks are stepped over, and nothing is copied out of the input.
func Certificates(data []byte) (Result, error) {
	res := Result{HadPrivateKey: ContainsPrivateKey(data)}

	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			res.Certificates = append(res.Certificates, cert)
		}
	}
	if len(res.Certificates) > 0 {
		return res, nil
	}

	// Not PEM: try DER. A .crt/.cer is as often one as the other, and a host
	// does not name its files honestly.
	if parsed, err := x509.ParseCertificates(data); err == nil && len(parsed) > 0 {
		res.Certificates = parsed
		return res, nil
	}
	return res, ErrNoCertificates
}

// PKCS12 extracts the certificates from a .p12/.pfx bundle, discarding the key.
//
// SSLMate's implementation, not x/crypto/pkcs12: the latter handles PBES1 only
// and fails on the AES-based PBES2 that every current tool produces, so the
// standard-library route would silently find nothing in most real bundles while
// appearing to work.
//
// The private key is necessarily decrypted in memory — PKCS#12 offers no way to
// read the certificates without it — and is discarded into the blank identifier
// here. It is never returned, logged, or stored.
func PKCS12(data []byte, password string) (Result, error) {
	_, leaf, cas, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return Result{}, err
	}

	certs := make([]*x509.Certificate, 0, len(cas)+1)
	if leaf != nil {
		certs = append(certs, leaf)
	}
	certs = append(certs, cas...)
	if len(certs) == 0 {
		return Result{}, ErrNoCertificates
	}
	// A PKCS#12 bundle essentially always carries the key; that is what it is
	// for. Reported as present so the portfolio can say so.
	return Result{Certificates: certs, HadPrivateKey: true}, nil
}

// EncodePEM renders certificates for the wire, from their parsed DER.
func EncodePEM(certs []*x509.Certificate) string {
	var out bytes.Buffer
	for _, cert := range certs {
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	return out.String()
}

// LeafWithChain is one end-entity certificate and the certificates, from the
// same input, that actually issued it — nearest issuer first.
type LeafWithChain struct {
	Leaf  *x509.Certificate
	Chain []*x509.Certificate
}

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
// built by ChainFor from the input plus any extra issuers the caller knows of —
// Apache's separate SSLCertificateChainFile, for one — so a certificate that
// happens to share the file never rides along as somebody else's issuer.
func Leaves(certs []*x509.Certificate, issuers ...*x509.Certificate) []LeafWithChain {
	candidates := make([]*x509.Certificate, 0, len(certs)+len(issuers))
	candidates = append(candidates, certs...)
	candidates = append(candidates, issuers...)

	var out []LeafWithChain
	seen := map[string]bool{}
	for _, cert := range certs {
		if cert.IsCA || seen[string(cert.Raw)] {
			continue
		}
		seen[string(cert.Raw)] = true
		out = append(out, LeafWithChain{Leaf: cert, Chain: ChainFor(cert, candidates)})
	}
	return out
}

// ChainFor walks upward from cert through the candidates, taking at each step
// the certificate that ISSUED the current one, and returns them leaf-side
// first. It stops at a self-signed certificate, at a missing link, or on a
// cycle. Nothing that did not sign its way into the chain is in it.
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
func ChainFor(cert *x509.Certificate, candidates []*x509.Certificate) []*x509.Certificate {
	var chain []*x509.Certificate
	visited := map[string]bool{string(cert.Raw): true}
	current := cert
	for !selfSigned(current) {
		next := issuerOf(current, candidates, visited)
		if next == nil {
			break
		}
		visited[string(next.Raw)] = true
		chain = append(chain, next)
		current = next
	}
	return chain
}

func issuerOf(cert *x509.Certificate, candidates []*x509.Certificate, visited map[string]bool) *x509.Certificate {
	for _, ca := range candidates {
		if visited[string(ca.Raw)] {
			continue // Itself, a duplicate of one already taken, or a cycle.
		}
		if ca.BasicConstraintsValid && !ca.IsCA {
			continue
		}
		if !bytes.Equal(ca.RawSubject, cert.RawIssuer) {
			continue
		}
		if ca.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil {
			return ca
		}
	}
	return nil
}

func selfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}
