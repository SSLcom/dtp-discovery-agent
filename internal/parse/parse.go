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

// Leaf picks the end-entity certificate out of what a store held, with
// everything else as its chain — and reports whether there was one at all.
//
// TAKING THE FIRST CERTIFICATE IS NOT GOOD ENOUGH, for two separate reasons.
//
// Order is not guaranteed. A bundle is a concatenation, and plenty of tools
// write the chain before the certificate it belongs to. Reporting an
// intermediate as the deployed certificate gives an operator the wrong expiry
// date for the thing that will actually break.
//
// And a file may hold no end-entity certificate at all. That is what a TRUST
// STORE is — /etc/ssl/certs/ca-certificates.crt, a JDK cacerts, a chain file on
// its own — and they are everywhere. Treating one as a deployment reports a CA
// root nobody chose, carrying a hundred and twenty others as its "chain", from
// every host in an estate. It is not a deployment, it is the list of issuers a
// machine is willing to believe, and mixing the two buries the certificates a
// member is actually paying to keep track of.
//
// So `found` is false for a store of nothing but CA certificates, and the
// caller decides. A collector reading a file it merely came across skips it. A
// collector reading a file a web server was CONFIGURED to serve reports it
// anyway, because whatever is in there is what that site presents.
func Leaf(certs []*x509.Certificate) (leaf *x509.Certificate, chain []*x509.Certificate, found bool) {
	for i, cert := range certs {
		if cert.IsCA {
			continue
		}
		chain = make([]*x509.Certificate, 0, len(certs)-1)
		chain = append(chain, certs[:i]...)
		chain = append(chain, certs[i+1:]...)
		return cert, chain, true
	}
	return nil, nil, false
}
