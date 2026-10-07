package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SSLcom/dtp-discovery-agent/internal/collect"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return &Signer{Key: key, Fingerprint: hex.EncodeToString(sum[:])}
}

// ── the two fields whose absence changes behaviour silently ─────────────────

// Nothing on the server reads this header; the host's rate limiter does,
// because middleware cannot parse a JSON body. Dropping it costs the whole
// fleet its per-agent bucket and nothing anywhere reports an error — which is
// why it is asserted here rather than left to integration testing.
func TestTokenRequestCarriesTheFingerprintHeader(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-DTP-Agent-Fingerprint")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "t", "expires_in": 900})
	}))
	defer server.Close()

	signer := testSigner(t)
	client := New(server.URL, "test")
	if err := client.Authenticate(context.Background(), signer); err != nil {
		t.Fatal(err)
	}
	if got != signer.Fingerprint {
		t.Errorf("header = %q, want the agent fingerprint %q", got, signer.Fingerprint)
	}
}

// Only the FINAL page names the collectors that finished, and only collectors
// that actually finished are named. It is the sole thing that lets DTP conclude
// a certificate is gone.
func TestOnlyTheFinalPageDeclaresCompletedSources(t *testing.T) {
	var pages []InventoryPage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/inventory") {
			var page InventoryPage
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &page)
			pages = append(pages, page)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"run_id": "r", "status": "completed"})
	}))
	defer server.Close()

	client := New(server.URL, "test")
	results := []collect.Result{
		{Source: collect.SourceFile, Completed: true, Observations: manyObservations(MaxObservationsPerPage + 5)},
		// Did NOT finish — a permission error means certificates were unseen,
		// not removed, so this source must not be declared.
		{Source: collect.SourceListener, Completed: false,
			Errors: []collect.Error{{Collector: "listener", Error: "permission denied"}}},
	}

	if _, err := Report(context.Background(), client, "run-1", time.Now(), results); err != nil {
		t.Fatal(err)
	}
	if len(pages) != 2 {
		t.Fatalf("want 2 pages for %d observations, got %d", MaxObservationsPerPage+5, len(pages))
	}
	if len(pages[0].CompletedSources) != 0 || pages[0].Final {
		t.Error("the first page must not be final nor declare completed sources")
	}
	if !pages[1].Final {
		t.Error("the last page must be final")
	}
	if want := []string{collect.SourceFile}; len(pages[1].CompletedSources) != 1 || pages[1].CompletedSources[0] != want[0] {
		t.Errorf("completed_sources = %v, want only the collector that finished", pages[1].CompletedSources)
	}
	if len(pages[1].CollectorErrors) != 1 {
		t.Error("the failing collector's error must be reported")
	}
}

func TestEveryPageCarriesTheSameRunID(t *testing.T) {
	var ids []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var page InventoryPage
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &page)
		ids = append(ids, page.RunID)
		_ = json.NewEncoder(w).Encode(map[string]any{"run_id": page.RunID})
	}))
	defer server.Close()

	results := []collect.Result{{Source: collect.SourceFile, Completed: true,
		Observations: manyObservations(MaxObservationsPerPage * 2)}}
	if _, err := Report(context.Background(), New(server.URL, "t"), "run-x", time.Now(), results); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if id != "run-x" {
			t.Fatalf("page carried run id %q; the server folds pages by that id", id)
		}
	}
}

// A host with no certificates still reports, or "found nothing" and "never ran"
// are indistinguishable in the portfolio.
func TestAHostWithNothingStillReports(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"run_id": "r"})
	}))
	defer server.Close()

	results := []collect.Result{{Source: collect.SourceFile, Completed: true}}
	if _, err := Report(context.Background(), New(server.URL, "t"), "run-0", time.Now(), results); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("want exactly one (empty, final) page, got %d", calls)
	}
}

// ── pending approval is not a failure ────────────────────────────────────────

// 202 is a 2xx, so a client that only checks `err != nil` accepts it as success
// and proceeds with an empty bearer token. The installer would look like it
// worked and every later call would fail for no stated reason.
func TestPendingApprovalIsDistinguishedFromSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "pending_approval", "retry_after": 30,
		})
	}))
	defer server.Close()

	err := New(server.URL, "t").Authenticate(context.Background(), testSigner(t))
	var pending *ErrPendingApproval
	if err == nil {
		t.Fatal("a 202 must not read as success")
	}
	if !asPending(err, &pending) {
		t.Fatalf("want ErrPendingApproval, got %T: %v", err, err)
	}
	if pending.RetryAfter != 30*time.Second {
		t.Errorf("retry after = %s, want 30s", pending.RetryAfter)
	}
}

func TestRefusedAgentIsTerminalNotRetried(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "refused", "agent_status": "revoked"})
	}))
	defer server.Close()

	err := New(server.URL, "t").Authenticate(context.Background(), testSigner(t))
	var refused *ErrRefused
	if !asRefused(err, &refused) {
		t.Fatalf("want ErrRefused, got %T: %v", err, err)
	}
	if refused.AgentStatus != "revoked" {
		t.Errorf("agent status = %q", refused.AgentStatus)
	}
}

// ── the outbound guard ───────────────────────────────────────────────────────

// The last line before the network. It should never fire — Observation has no
// field for key bytes — so this test forges one into a field that DOES go on
// the wire and asserts the request is refused locally rather than sent.
func TestKeyMaterialIsRefusedBeforeItLeavesTheProcess(t *testing.T) {
	reached := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		_ = json.NewEncoder(w).Encode(map[string]any{"run_id": "r"})
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	leaked := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))

	_, err := New(server.URL, "t").Inventory(context.Background(), InventoryPage{
		RunID:        "run-leak",
		Observations: []collect.Observation{{CertificatePEM: leaked, Source: "file", Location: "/x"}},
	})
	if err == nil {
		t.Fatal("a payload containing a private key must be refused")
	}
	if !strings.Contains(err.Error(), "private key material") {
		t.Errorf("unexpected error: %v", err)
	}
	if reached {
		t.Fatal("the request reached the network; the guard must stop it locally")
	}
}

// THE WORDS ARE NOT THE KEY. Paths, aliases, server names and error text come
// from the host, and "private key" is an ordinary thing to call a directory or
// a keystore alias. Up to v0.5.0 the guard matched those two words anywhere in
// the body, so one directory named "Private Key Backups" in a scanned root —
// or a keystore alias "server private key" — refused EVERY page of EVERY run on
// that host, leaving its whole inventory unreported for as long as the name
// stayed. Measured with the shipped binary: one such directory, zero pages.
func TestNamesThatMentionPrivateKeysAreNotKeyMaterial(t *testing.T) {
	reached := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		_ = json.NewEncoder(w).Encode(map[string]any{"run_id": "r"})
	}))
	defer server.Close()

	cert := testCertificatePEM(t)
	_, err := New(server.URL, "t").Inventory(context.Background(), InventoryPage{
		RunID: "run-names",
		Observations: []collect.Observation{
			{CertificatePEM: cert, ChainPEM: cert, Source: "file",
				Location:           "/srv/Private Key Backups/site.pem",
				PrivateKeyPresent:  true,
				PrivateKeyLocation: "/etc/ssl/private key.pem"},
			{CertificatePEM: cert, Source: "java_keystore",
				Location: "/opt/app/keystore.jks:server private key",
				Binding:  map[string]string{"alias": "server private key"}},
		},
		CollectorErrors: []collect.Error{{Collector: "java_keystore", Location: "/opt/app/k.jks",
			Error: `entry "old private key": unexpected end of data`}},
	})
	if err != nil {
		t.Fatalf("a page whose NAMES mention a private key must be sent: %v", err)
	}
	if reached != 1 {
		t.Fatalf("the server received %d requests, want 1", reached)
	}
}

// What the guard is FOR still holds in every field: real key material is
// refused locally, in a certificate field, in a chain field, and in a field that
// has no business carrying PEM at all — the "future field" the guard exists for.
func TestKeyMaterialIsRefusedInAnyField(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	leaked := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	// Truncated: pem.Decode rejects it, but it is still a key's text. In a PEM
	// field that is refused; the substring rule still applies THERE.
	truncated := leaked[:len(leaked)/2]
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	cert := testCertificatePEM(t)

	for name, obs := range map[string]collect.Observation{
		"certificate":           {CertificatePEM: leaked, Source: "file", Location: "/x"},
		"chain":                 {CertificatePEM: cert, ChainPEM: cert + leaked, Source: "file", Location: "/x"},
		"truncated in chain":    {CertificatePEM: cert, ChainPEM: cert + truncated, Source: "file", Location: "/x"},
		"location":              {CertificatePEM: cert, Source: "file", Location: "/x/" + leaked},
		"key location":          {CertificatePEM: cert, Source: "file", Location: "/x", PrivateKeyLocation: leaked},
		"binding":               {CertificatePEM: cert, Source: "file", Location: "/x", Binding: map[string]string{"note": leaked}},
		"pkcs8 in a binding":    {CertificatePEM: cert, Source: "file", Location: "/x", Binding: map[string]string{"note": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))}},
		"lowercase armor label": {CertificatePEM: cert, Source: "file", Location: "/x", Binding: map[string]string{"note": strings.ReplaceAll(leaked, "EC PRIVATE KEY", "ec private key")}},
		"a binding's KEY":       {CertificatePEM: cert, Source: "file", Location: "/x", Binding: map[string]string{leaked: "x"}},
		"truncated armor":       {CertificatePEM: cert, Source: "file", Location: "/x/" + strings.TrimSuffix(strings.SplitN(leaked, "\n", 2)[0], "-----")},
		"RFC 4716 armor":        {CertificatePEM: cert, Source: "file", Location: "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nAAAA"},
		"unicode dashes":        {CertificatePEM: cert, Source: "file", Location: strings.ReplaceAll(leaked, "-", "\u2010")},
		"no-break space":        {CertificatePEM: cert, Source: "file", Location: strings.ReplaceAll(leaked, "PRIVATE KEY", "PRIVATE\u00a0KEY")},
	} {
		t.Run(name, func(t *testing.T) {
			reached := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				_ = json.NewEncoder(w).Encode(map[string]any{"run_id": "r"})
			}))
			defer server.Close()

			_, err := New(server.URL, "t").Inventory(context.Background(), InventoryPage{
				RunID: "run-leak", Observations: []collect.Observation{obs},
			})
			if err == nil || !strings.Contains(err.Error(), "private key material") {
				t.Fatalf("want the guard's refusal, got %v", err)
			}
			if reached {
				t.Fatal("the request reached the network")
			}
		})
	}
	// And in a collector error, which is free text too.
	_, err := New("http://127.0.0.1:0", "t").Inventory(context.Background(), InventoryPage{
		RunID:           "run-leak",
		CollectorErrors: []collect.Error{{Collector: "file", Error: "read: " + leaked}},
	})
	if err == nil || !strings.Contains(err.Error(), "private key material") {
		t.Fatalf("a key in a collector error must be refused, got %v", err)
	}
}

func testCertificatePEM(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "guard.invalid"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// ── assertion ────────────────────────────────────────────────────────────────

// The nonce is single-use on the server: a cached assertion would authenticate
// exactly once and then fail in a way that looks like a server fault.
func TestEachAssertionIsFresh(t *testing.T) {
	signer := testSigner(t)
	first, err := signer.Assertion()
	if err != nil {
		t.Fatal(err)
	}
	second, err := signer.Assertion()
	if err != nil {
		t.Fatal(err)
	}
	a, b := first.(assertion), second.(assertion)
	if a.Nonce == b.Nonce {
		t.Fatal("two assertions shared a nonce; the second would be refused as a replay")
	}
	if a.Signature == b.Signature {
		t.Fatal("two assertions shared a signature")
	}
}

// The server verifies the whole canonical string against the key it looked up.
// The fingerprint being INSIDE it is what stops one agent's fingerprint being
// paired with another agent's signature.
func TestAssertionSignsTheServersCanonicalString(t *testing.T) {
	signer := testSigner(t)
	raw, err := signer.Assertion()
	if err != nil {
		t.Fatal(err)
	}
	a := raw.(assertion)

	signed := strings.Join([]string{
		assertionPrefix, a.KeyFingerprint, a.IssuedAt, a.Nonce, assertionAudience,
	}, "\n")
	digest := sha256.Sum256([]byte(signed))
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&signer.Key.PublicKey, digest[:], sig) {
		t.Fatal("signature does not verify over the string the server reconstructs")
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func manyObservations(n int) []collect.Observation {
	out := make([]collect.Observation, n)
	for i := range out {
		out[i] = collect.Observation{Source: collect.SourceFile, Location: "/etc/ssl/x.pem"}
	}
	return out
}

func asPending(err error, target **ErrPendingApproval) bool {
	p, ok := err.(*ErrPendingApproval)
	if ok {
		*target = p
	}
	return ok
}

func asRefused(err error, target **ErrRefused) bool {
	r, ok := err.(*ErrRefused)
	if ok {
		*target = r
	}
	return ok
}
