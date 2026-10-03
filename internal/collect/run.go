package collect

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// Options is everything a scan can be told.
type Options struct {
	File         Bounds
	Keystores    KeystoreBounds
	OSStore      []string
	ServerConfig ServerConfigBounds
	Listener     ListenerBounds

	// Disabled names sources this host will not collect. The agent runs on
	// machines its owner is answerable for, and not every owner wants every
	// source — probing local TLS listeners opens connections to live services,
	// which a security team may reasonably forbid.
	Disabled []string
}

// All is THE list of collectors this build has, and the only one. The --without
// help text, the validation that rejects a misspelt source, and the collectors
// a scan runs all derive from here, so adding one cannot leave a second list
// quietly stale behind it.
//
// THE ORDER IS LOAD-BEARING. ServerConfig runs before Listener because it is
// what discovers the names a name-based virtual host answers to, and a probe
// without those names gets the default certificate and nothing else. Reversing
// them leaves every site but the first invisible on exactly the hosts that have
// the most of them — and nothing would look broken.
func All(opts Options) []Collector {
	return []Collector{
		&FS{Bounds: opts.File},
		&Keystores{Bounds: opts.Keystores},
		&OSStore{Stores: opts.OSStore},
		&ServerConfig{Bounds: opts.ServerConfig},
		&Listener{Bounds: opts.Listener},
	}
}

// Names is every source this build can collect.
func Names() []string {
	all := All(Options{})
	names := make([]string, 0, len(all))
	for _, c := range all {
		names = append(names, c.Source())
	}
	return names
}

// ValidateDisabled refuses a source name this build does not have.
//
// Silently ignoring a typo is much the worse failure: `--without listner` would
// leave the probe RUNNING on a host whose owner believes they turned it off,
// and nothing in the output would say so.
func ValidateDisabled(disabled []string) error {
	known := Names()
	for _, name := range disabled {
		if !slices.Contains(known, name) {
			return fmt.Errorf("unknown source %q: this agent collects %s", name, strings.Join(known, ", "))
		}
	}
	return nil
}

// Informed is a collector that can use what the collectors before it found.
//
// The listener probe is the one that needs it: a name-based virtual host
// answers a probe carrying no SNI with its DEFAULT certificate, so without the
// names the configuration collector discovered, the other twenty sites on the
// machine cannot be seen at all.
type Informed interface {
	Inform(earlier []Result)
}

// Limits on what one run may report, across every source.
//
// ONE FILE CAN BE HUNDREDS OF OBSERVATIONS, since every end-entity certificate
// in it is reported, and each carries its own chain. A host whose scanned
// directories somebody else can write to could otherwise make a run of a
// million observations, held in memory and uploaded page after page. Past
// either limit the run stops collecting, and says so (see observe).
const (
	// MaxObservationsPerRun: forty pages at the protocol's 500. A large web
	// host — a few thousand sites, each seen as a file, in its server
	// configuration and on its listener — comes to around ten thousand.
	MaxObservationsPerRun = 20000

	// MaxObservationBytesPerRun bounds the certificates and chains those
	// observations carry. A real observation is a few KiB of PEM, so this is
	// MaxObservationsPerRun of them with room to spare; it is what binds when
	// a planted file pairs many leaves with one long chain of oversized
	// certificates, which every one of them would otherwise carry in full.
	MaxObservationBytesPerRun = 128 << 20
)

// Run executes the enabled collectors in order, giving each what the earlier
// ones found.
func Run(ctx context.Context, opts Options) []Result {
	return runWithin(ctx, opts, &runCap{maxCount: MaxObservationsPerRun, maxBytes: MaxObservationBytesPerRun})
}

func runWithin(ctx context.Context, opts Options, limit *runCap) []Result {
	ctx = context.WithValue(ctx, runCapKey{}, limit)
	var out []Result
	for _, c := range All(opts) {
		if slices.Contains(opts.Disabled, c.Source()) {
			continue
		}
		if limit.full {
			// Not run at all, and not complete: nothing it would have found
			// may be marked gone because the run filled up before reaching it.
			out = append(out, Result{Source: c.Source(), Errors: []Error{limit.error(c.Source(), "was not run")}, capped: true})
			continue
		}
		if informed, ok := c.(Informed); ok {
			informed.Inform(out)
		}
		out = append(out, c.Collect(ctx))
	}
	return out
}

// runCap is what a run has reported so far, against its limits. Collectors run
// one at a time and each records from one goroutine, so it needs no lock.
type runCap struct {
	maxCount, maxBytes int
	count, bytes       int
	full               bool
}

type runCapKey struct{}

func (c *runCap) error(source, what string) Error {
	return Error{
		Collector: source,
		Error: fmt.Sprintf("this run reached its limit of %d certificates (or %d MiB of them) and the rest of this source %s; nothing it would have found is marked absent",
			c.maxCount, c.maxBytes>>20, what),
	}
}

// observe adds o to the result while the run has room for it, and reports
// whether it did. The first observation refused marks the collector incomplete
// — the server must not take what it never received as removed — and says so
// in its errors, once; the scan prints those, and the server records them with
// the run. The protocol has no other way to say "truncated", and needs none:
// an incomplete source with a named reason is exactly that.
//
// A collector run outside Run (a test, one source on its own) has no limit.
func (r *Result) observe(ctx context.Context, o Observation) bool {
	limit, _ := ctx.Value(runCapKey{}).(*runCap)
	if limit == nil {
		r.Observations = append(r.Observations, o)
		return true
	}
	size := len(o.CertificatePEM) + len(o.ChainPEM)
	if limit.full || limit.count+1 > limit.maxCount || limit.bytes+size > limit.maxBytes {
		limit.full = true
		if !r.capped {
			r.capped = true
			r.Completed = false
			r.Errors = append(r.Errors, limit.error(r.Source, "was not reported"))
		}
		return false
	}
	limit.count++
	limit.bytes += size
	r.Observations = append(r.Observations, o)
	return true
}

// ReachedRunLimit reports whether these results were cut short by the run's
// limits, for a caller that should say so in its own log as well as in what it
// uploads.
func ReachedRunLimit(results []Result) bool {
	for _, r := range results {
		if r.capped {
			return true
		}
	}
	return false
}

// runFull reports whether the run has stopped taking observations, so a walk
// can stop rather than read files whose findings would be refused.
func runFull(ctx context.Context) bool {
	limit, _ := ctx.Value(runCapKey{}).(*runCap)
	return limit != nil && limit.full
}
