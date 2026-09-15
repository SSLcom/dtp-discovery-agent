package transport

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// The assertion the agent signs to prove it holds its key.
//
// A DETACHED SIGNATURE, not a JWT, and the difference is the point: DTP already
// holds this agent's public key, so the signing algorithm is a property of the
// key DTP stored and is never read from the request. There is no `alg` field to
// confuse, no `none`, and no header an attacker controls.
const (
	assertionPrefix   = "DTP-DISCOVERY-AGENT-ASSERTION-v1"
	assertionAudience = "dtp-discovery"
	nonceBytes        = 24
)

type Signer struct {
	Key         *ecdsa.PrivateKey
	Fingerprint string
}

type assertion struct {
	KeyFingerprint string `json:"key_fingerprint"`
	IssuedAt       string `json:"issued_at"`
	Nonce          string `json:"nonce"`
	Signature      string `json:"signature"`
}

// Assertion produces a freshly signed, single-use assertion.
//
// The nonce is random per call and the server records it: replaying a captured
// assertion inside its five-minute window is refused. So this is never cached —
// a Signer that returned the same assertion twice would work exactly once and
// then fail in a way that looks like a server fault.
func (s *Signer) Assertion() (any, error) {
	nonceRaw := make([]byte, nonceBytes)
	if _, err := rand.Read(nonceRaw); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceRaw)
	issuedAt := time.Now().UTC().Format(time.RFC3339)

	// The FINGERPRINT IS INSIDE THE SIGNED STRING. That is what stops one
	// agent's fingerprint being paired with another agent's signature — the
	// server verifies the whole string against the key it looked up, so a
	// mismatched pair fails on the signature rather than being trusted.
	signed := strings.Join([]string{
		assertionPrefix, s.Fingerprint, issuedAt, nonce, assertionAudience,
	}, "\n")

	digest := sha256.Sum256([]byte(signed))
	sig, err := s.Key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign assertion: %w", err)
	}

	return assertion{
		KeyFingerprint: s.Fingerprint,
		IssuedAt:       issuedAt,
		Nonce:          nonce,
		Signature:      base64.StdEncoding.EncodeToString(sig),
	}, nil
}
