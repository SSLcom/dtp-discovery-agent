package transport

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
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

// The document shows an implementer the exact string to sign. This EXTRACTS
// that recipe from PROTOCOL.md, fills in a real assertion's values, and checks
// the signature the client produced verifies over it.
//
// The first version of this test hardcoded the prefix and audience and compared
// them to the package constants — so it never opened the document at all, and a
// swapped line, an extra line or a trailing newline in the published recipe
// would have passed. Bugbot caught that. A test named for the document has to
// read the document.
func TestDocumentedAssertionRecipeProducesAValidSignature(t *testing.T) {
	recipeTemplate := extractSigningRecipe(t)

	signer := testSigner(t)
	raw, err := signer.Assertion()
	if err != nil {
		t.Fatal(err)
	}
	a := raw.(assertion)

	recipe := recipeTemplate
	for placeholder, value := range map[string]string{
		"<key_fingerprint>": a.KeyFingerprint,
		"<issued_at>":       a.IssuedAt,
		"<nonce>":           a.Nonce,
	} {
		if !strings.Contains(recipe, placeholder) {
			t.Fatalf("the documented recipe has no %s placeholder:\n%q", placeholder, recipe)
		}
		recipe = strings.Replace(recipe, placeholder, value, 1)
	}

	// Signed exactly as the document instructs: SHA-256 of the joined string.
	digest := sha256.Sum256([]byte(recipe))
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&signer.Key.PublicKey, digest[:], sig) {
		t.Fatalf("a signature from this client does NOT verify over the recipe the document publishes.\n"+
			"An implementer following PROTOCOL.md would be rejected.\nrecipe: %q", recipe)
	}
}

// extractSigningRecipe pulls the fenced block from PROTOCOL.md that shows the
// string to sign — identified by its placeholders rather than by position, so
// reordering the document does not silently select the wrong block.
func extractSigningRecipe(t *testing.T) string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "PROTOCOL.md"))
	if err != nil {
		t.Fatalf("reading PROTOCOL.md: %v", err)
	}
	// Git hands this file to a Windows checkout with CRLF line endings, and the
	// signed string is defined by its CONTENT, not by how the repository was
	// cloned. Without this the test fails on Windows and on nobody else's
	// machine, over a difference that no client would ever see.
	raw = []byte(strings.ReplaceAll(string(raw), "\r\n", "\n"))

	var found []string
	for _, block := range strings.Split(string(raw), "```")[1:] {
		if strings.Contains(block, "<key_fingerprint>") && strings.Contains(block, "<nonce>") {
			// Drop an info string on the opening fence, and the newline the
			// fence itself contributes — but keep everything else byte for
			// byte, because a stray blank line IS the bug this looks for.
			body := block
			if i := strings.Index(body, "\n"); i >= 0 {
				body = body[i+1:]
			}
			found = append(found, strings.TrimSuffix(body, "\n"))
		}
	}

	switch len(found) {
	case 1:
		return found[0]
	case 0:
		t.Fatal("PROTOCOL.md no longer contains a signing recipe block")
	default:
		t.Fatalf("PROTOCOL.md has %d signing-recipe blocks; the test cannot tell which is authoritative", len(found))
	}
	return ""
}
