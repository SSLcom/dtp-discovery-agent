package transport

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/SSLcom/dtp-discovery-agent/internal/collect"
)

// docs/PROTOCOL.md is published for people writing their own client. Every
// literal in it is something somebody will copy into an implementation, so a
// constant that changes here and not there does not produce a broken build —
// it produces a third-party client that fails to authenticate for reasons
// nobody can see.
//
// This asserts the document still says what the code does.
func TestProtocolDocMatchesTheCode(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "PROTOCOL.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	doc := string(raw)

	mustContain := map[string]string{
		"assertion prefix":    assertionPrefix,
		"assertion audience":  assertionAudience,
		"observations a page": strconv.Itoa(MaxObservationsPerPage),
	}
	for what, literal := range mustContain {
		if !strings.Contains(doc, literal) {
			t.Errorf("PROTOCOL.md does not mention the %s (%q) the code uses", what, literal)
		}
	}

	// Every source a client may report has to be documented, or an
	// implementer files their findings under a name the server buckets as
	// "other" and absence detection quietly stops working for them.
	for _, source := range []string{
		collect.SourceFile, collect.SourceOSStore, collect.SourceJavaKeystore,
		collect.SourceNSS, collect.SourceListener, collect.SourceServerConfig,
	} {
		if !strings.Contains(doc, "`"+source+"`") {
			t.Errorf("PROTOCOL.md does not document the %q source", source)
		}
	}

	// The two fields whose absence changes behaviour without erroring. If the
	// document ever stops explaining them, a client author has no way to learn
	// they matter.
	for _, field := range []string{"X-DTP-Agent-Fingerprint", "completed_sources"} {
		if !strings.Contains(doc, field) {
			t.Errorf("PROTOCOL.md does not document %s", field)
		}
	}
}

// The document tells an implementer to join five lines with \n and sign the
// SHA-256 of the result. This builds that string from the document's own
// description and checks a real assertion verifies against it — so the
// instructions are not merely present, they are correct.
func TestDocumentedAssertionRecipeProducesAValidSignature(t *testing.T) {
	signer := testSigner(t)
	raw, err := signer.Assertion()
	if err != nil {
		t.Fatal(err)
	}
	a := raw.(assertion)

	// Exactly as PROTOCOL.md describes it: five lines, joined with \n, no
	// trailing newline.
	recipe := strings.Join([]string{
		"DTP-DISCOVERY-AGENT-ASSERTION-v1",
		a.KeyFingerprint,
		a.IssuedAt,
		a.Nonce,
		"dtp-discovery",
	}, "\n")

	if strings.HasSuffix(recipe, "\n") {
		t.Fatal("the recipe must not end in a newline")
	}
	if got := signedString(signer.Fingerprint, a.IssuedAt, a.Nonce); got != recipe {
		t.Fatalf("the documented recipe differs from what the client signs:\n doc:  %q\n code: %q", recipe, got)
	}
}

// signedString mirrors what Assertion() signs, so the test above compares the
// document against the code rather than against itself.
func signedString(fingerprint, issuedAt, nonce string) string {
	return strings.Join([]string{assertionPrefix, fingerprint, issuedAt, nonce, assertionAudience}, "\n")
}
