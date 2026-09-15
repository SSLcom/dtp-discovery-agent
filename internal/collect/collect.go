// Package collect defines what the agent finds and the contract every collector
// meets. The collectors themselves live alongside this file, one per source.
package collect

import (
	"context"
	"time"
)

// Source values DTP understands. Anything a collector reports outside this set
// is filed by the server as "other" rather than guessed at — and "other" is a
// real source there, not a fallback, because absence is decided per source and
// mis-filing a collector's findings would let a different collector's completed
// scan mark them gone.
const (
	SourceFile         = "file"
	SourceOSStore      = "os_store"
	SourceJavaKeystore = "java_keystore"
	SourceNSS          = "nss"
	SourceListener     = "listener"
	SourceServerConfig = "server_config"
)

// Observation is one certificate seen in one place.
//
// THERE IS NO FIELD FOR PRIVATE KEY MATERIAL, and that is the design rather than
// an omission. The agent records THAT a key sits beside a certificate and where,
// because an operator needs to know a key exists and is mode 0644 — but the
// bytes are never read into this struct, so no later change to a collector can
// leak them by populating a field that was lying around. transport.guard is the
// second line; this is the first.
type Observation struct {
	CertificatePEM string            `json:"certificate_pem"`
	ChainPEM       string            `json:"chain_pem,omitempty"`
	Source         string            `json:"source"`
	Location       string            `json:"location"`
	Binding        map[string]string `json:"binding,omitempty"`

	PrivateKeyPresent  bool   `json:"private_key_present"`
	PrivateKeyLocation string `json:"private_key_location,omitempty"`
	FileMode           string `json:"file_mode,omitempty"`
	FileOwner          string `json:"file_owner,omitempty"`

	ObservedAt time.Time `json:"observed_at"`
}

// Error is a collector saying what it could not do. Reported to DTP so a member
// can see that a keystore was unreadable rather than concluding the host has no
// certificates in it.
type Error struct {
	Collector string `json:"collector"`
	Error     string `json:"error"`
	Location  string `json:"location,omitempty"`
}

// Result is one collector's outcome.
//
// `Completed` is the load-bearing field. A collector reports it true ONLY when
// it finished its whole sweep cleanly, because DTP uses it to decide that a
// certificate previously seen by this source is gone. A collector that hit a
// permission error saw certificates it could not see — not certificates that
// were removed — so it reports false and nothing of its is marked absent.
type Result struct {
	Source       string
	Observations []Observation
	Errors       []Error
	Completed    bool
}

// Collector is one way of finding certificates on a host.
type Collector interface {
	// Source is the DTP source name every observation of this collector carries.
	Source() string
	// Collect sweeps the host. It returns a Result rather than an error: a
	// collector that fails has still partly succeeded, and what it did find is
	// worth reporting as long as Completed says not to trust its silence.
	Collect(ctx context.Context) Result
}
