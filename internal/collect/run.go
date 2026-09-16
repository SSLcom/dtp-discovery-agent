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

// Run executes the enabled collectors in order, giving each what the earlier
// ones found.
func Run(ctx context.Context, opts Options) []Result {
	var out []Result
	for _, c := range All(opts) {
		if slices.Contains(opts.Disabled, c.Source()) {
			continue
		}
		if informed, ok := c.(Informed); ok {
			informed.Inform(out)
		}
		out = append(out, c.Collect(ctx))
	}
	return out
}
