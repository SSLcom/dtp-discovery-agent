package collect

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // a thumbprint IS SHA-1; it is an identifier, not a security claim
	"crypto/x509"
	"encoding/hex"
	"strings"
	"time"

	"github.com/SSLcom/dtp-discovery-agent/internal/parse"
)

// storeEntry is one certificate as an operating system's own store holds it.
type storeEntry struct {
	// Store is what a person would type to find it again: a Windows store path
	// like `LocalMachine\My`, or the path of a macOS keychain.
	Store       string
	Certificate *x509.Certificate
	// HasPrivateKey is what separates a certificate this machine can SERVE from
	// one it merely trusts. On Windows both live in the same store, so without
	// it the personal store of a web server and a pile of imported trust
	// anchors are indistinguishable.
	HasPrivateKey bool
	FriendlyName  string
}

// storeFailure is a store the agent could not read. Kept apart from a store
// that was read and held nothing: the first means certificates went unseen and
// must never be treated as removed.
type storeFailure struct {
	Store string
	Err   error
}

// OSStore finds the certificates the operating system itself is holding.
//
// On Windows this is where a certificate LIVES: IIS, SQL Server, RDP and WinRM
// all bind to a store entry rather than to a file, so there is no PEM anywhere
// on the disk to find and every file-based collector reports that machine as
// bare. On macOS it is the system keychain.
//
// Trust anchors come back too, in their hundreds, and are dropped by the same
// rule that drops a cacerts: a store entry with no end-entity certificate is a
// list of issuers the machine believes, not something deployed on it.
type OSStore struct {
	// Stores overrides which stores to read. Empty means the platform's usual
	// ones. Tests set it; so can a member whose certificates are somewhere
	// unusual.
	Stores []string
}

func (c *OSStore) Source() string { return SourceOSStore }

// osStores is the platform's own reader. A variable rather than a direct call
// so that the decisions made ABOVE it — which entries are trust anchors, what a
// store that would not open does to the sweep — are testable on every platform
// rather than only on the one they happen to matter on.
var osStores = readOSStores

func (c *OSStore) Collect(ctx context.Context) Result {
	res := Result{Source: SourceOSStore, Completed: true}

	entries, failures, err := osStores(ctx, c.Stores)
	if err != nil {
		// The platform has no store the agent can read — every Linux host, and
		// most of what this runs on. Not a fault and not worth an error in a
		// member's portfolio, but the source cannot claim a sweep it did not do.
		res.Completed = false
		return res
	}

	for _, failure := range failures {
		// A store that would not open holds certificates the agent did not see.
		// Saying the sweep completed would let a later run conclude they had
		// been removed from a machine where they are sitting untouched.
		res.Completed = false
		res.Errors = append(res.Errors, Error{
			Collector: SourceOSStore, Location: failure.Store, Error: failure.Err.Error(),
		})
	}

	for _, entry := range entries {
		if entry.Certificate == nil {
			continue
		}
		if trustAnchor(entry) {
			continue
		}

		binding := map[string]string{
			"store":      entry.Store,
			"thumbprint": thumbprint(entry.Certificate),
		}
		if entry.FriendlyName != "" {
			// What the administrator called it in the certificates snap-in. It
			// is often the only human-readable label on a Windows certificate.
			binding["friendly_name"] = entry.FriendlyName
		}

		res.Observations = append(res.Observations, Observation{
			CertificatePEM: parse.EncodePEM([]*x509.Certificate{entry.Certificate}),
			Source:         SourceOSStore,
			// The STORE, not the certificate. Several certificates in one store
			// are several placements at one location, which the platform keys
			// apart by the certificate itself.
			Location: entry.Store,
			Binding:  binding,
			// The key is held BY THE STORE, and on Windows very often by a
			// hardware provider behind it. There is no file to point an
			// operator at, so the store is the location.
			PrivateKeyPresent:  entry.HasPrivateKey,
			PrivateKeyLocation: keyLocation(entry.Store, entry.HasPrivateKey),
			ObservedAt:         time.Now().UTC(),
		})
	}
	return res
}

// trustAnchor reports whether a store entry is something this machine BELIEVES
// rather than something it SERVES. There are hundreds of the first on every
// machine and a handful of the second, so getting it wrong drowns the findings.
//
// basicConstraints ALONE IS NOT ENOUGH, which was measured rather than guessed:
// on a Windows runner, fourteen certificates in LocalMachine\Root carry no
// basicConstraints extension at all — they predate it being required — so Go
// reports IsCA false and every one of them would have arrived in a member's
// portfolio as a deployed certificate, from every Windows host they own.
//
// A self-signed certificate with no private key on this machine is the same
// thing: an issuer somebody imported. The private-key qualifier is load-bearing
// in the other direction — a self-signed certificate this machine HOLDS THE KEY
// for is a real deployment, and internal infrastructure is full of them.
func trustAnchor(entry storeEntry) bool {
	cert := entry.Certificate
	if cert.IsCA {
		return true
	}
	if bytes.Equal(cert.RawSubject, cert.RawIssuer) && !entry.HasPrivateKey {
		return true
	}
	return false
}

// thumbprint is the SHA-1 hash Windows shows in the certificates snap-in and
// the one `netsh http show sslcert` prints. It is reported so a finding can be
// matched against what an administrator sees on their own screen — it is an
// identifier here, and nothing is trusted because of it.
func thumbprint(cert *x509.Certificate) string {
	sum := sha1.Sum(cert.Raw) //nolint:gosec // see above
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// parseIdentities reads `security find-identity -v` output into the set of
// certificate thumbprints this machine holds a private key for.
//
// It lives here rather than beside the rest of the macOS code so that it is
// tested on every platform. A parser that only ever runs on one runner is one
// nobody reads the failures of.
func parseIdentities(out string) map[string]bool {
	identities := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		// `  1) A1B2C3…40 hex chars… "Some Certificate Name"`
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		hash := strings.ToUpper(fields[1])
		if len(hash) == 40 && isHex(hash) {
			identities[hash] = true
		}
	}
	return identities
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// parseAgain re-parses DER the agent is holding onto. Used by the Windows tests
// to prove a certificate survived the enumeration that freed the memory it came
// out of — a certificate whose Raw still parses is one that was copied.
func parseAgain(der []byte) (*x509.Certificate, error) { return x509.ParseCertificate(der) }
