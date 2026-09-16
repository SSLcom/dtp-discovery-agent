// Command dtp-agent inventories the certificates on this host and reports them
// to the Digital Trust Platform.
//
// It is READ-ONLY. No write path is compiled into this version: it opens
// certificate files, records where they are, and uploads what it found. It never
// reads a private key, never installs anything, and never modifies a file.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/SSLcom/dtp-discovery-agent/internal/collect"
	"github.com/SSLcom/dtp-discovery-agent/internal/state"
	"github.com/SSLcom/dtp-discovery-agent/internal/transport"
)

// Version is stamped at build time: -ldflags "-X main.Version=1.2.3".
var Version = "dev"

const usage = `dtp-agent — certificate discovery for the Digital Trust Platform

  dtp-agent enroll --server URL --account ID [--token TOKEN] [--without SOURCE]
        Generate this agent's keypair (once) and ask to join an account.
        Safe to re-run: enrolling again with a different account asks to move.
        --without records a source this host will not collect, e.g. listener.

  dtp-agent scan [--json] [--without SOURCE]
        Scan this host and print what was found. Uploads NOTHING — for seeing
        what the agent would report before letting it report.

  dtp-agent run [--once] [--without SOURCE]
        Scan and upload. Waits, rather than failing, while approval is pending.

  dtp-agent status
        What this agent is, what it last found, and whether DTP has heard from
        it. The first question support will ask.

  dtp-agent version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "enroll":
		err = cmdEnroll(ctx, os.Args[2:])
	case "scan":
		err = cmdScan(ctx, os.Args[2:])
	case "run":
		err = cmdRun(ctx, os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "version":
		fmt.Println(Version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "dtp-agent: %v\n", err)
		os.Exit(1)
	}
}

func stateFlag(fs *flag.FlagSet) *string {
	return fs.String("state", state.DefaultDir(), "state directory")
}

// roots is a repeatable --root, for a host that keeps its certificates
// somewhere the defaults do not look. Naming roots is always better than
// widening the default sweep: an agent that walks / on a machine with an NFS
// mount is the incident this product was meant to prevent.
type roots []string

func (r *roots) String() string { return strings.Join(*r, ",") }
func (r *roots) Set(v string) error {
	*r = append(*r, v)
	return nil
}

func rootsFlag(fs *flag.FlagSet) *roots {
	r := &roots{}
	fs.Var(r, "root", "directory to scan (repeatable; defaults to the usual TLS locations)")
	return r
}

// without is a repeatable --without, naming a source this host will not
// collect. Recorded at enrolment so the service unit needs no arguments, and
// accepted on scan/run so the effect can be seen before it is committed to.
func withoutFlag(fs *flag.FlagSet) *roots {
	r := &roots{}
	fs.Var(r, "without", "source not to collect: "+strings.Join(sourceNames(), ", ")+" (repeatable)")
	return r
}

// ── enroll ───────────────────────────────────────────────────────────────────

func cmdEnroll(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "", "DTP base URL, e.g. https://app.example.com")
	account := fs.String("account", "", "the DTP account id to join")
	token := fs.String("token", "", "enrollment token (optional)")
	scanRoots := rootsFlag(fs)
	skip := withoutFlag(fs)
	dir := stateFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *server == "" || *account == "" {
		return errors.New("--server and --account are required")
	}
	if err := validateSources(*skip); err != nil {
		return err
	}

	store, err := state.Open(*dir)
	if err != nil {
		return err
	}
	key, err := store.LoadOrCreateKey()
	if err != nil {
		return err
	}
	pub, err := state.PublicKeyPEM(key)
	if err != nil {
		return err
	}
	fingerprint, err := state.Fingerprint(key)
	if err != nil {
		return err
	}

	client := transport.New(*server, Version)
	resp, err := client.Register(ctx, transport.RegisterRequest{
		PublicKeyPEM: pub,
		AccountID:    *account,
		// The token is sent and then forgotten — it is never written to the
		// state directory. It admits an agent once; keeping it on disk would
		// turn a one-time secret into a standing one on a machine DTP does not
		// control.
		EnrollmentToken: *token,
		HostFacts:       hostFacts(),
	})
	if err != nil {
		return fmt.Errorf("registering with %s: %w", *server, err)
	}

	if err := store.SaveConfig(&state.Config{
		ServerURL:      *server,
		AccountID:      *account,
		AgentID:        resp.AgentID,
		RegistrationID: resp.RegistrationID,
		// Recorded here so the service unit can run `dtp-agent run` with no
		// arguments at all.
		ScanRoots:       *scanRoots,
		DisabledSources: *skip,
	}); err != nil {
		return err
	}

	fmt.Printf("Enrolled.\n  fingerprint  %s\n  status       %s\n  state        %s\n",
		fingerprint, resp.Status, store.Dir())
	if resp.Status != "approved" {
		fmt.Println("\nThis agent is waiting for an account admin to admit it.")
		fmt.Println("Give them the fingerprint above to check against this host.")
	}
	return nil
}

// ── scan ─────────────────────────────────────────────────────────────────────

// allCollectors is THE list of what this build can collect, and the only one.
// Every other place that needs to know — the --without help text, the
// validation that rejects a misspelt source, the collectors a scan actually
// runs — derives from here, so adding a collector cannot leave a second list
// quietly stale behind it.
func allCollectors(bounds collect.Bounds) []collect.Collector {
	return []collect.Collector{
		&collect.FS{Bounds: bounds},
		&collect.Listener{},
	}
}

func sourceNames() []string {
	all := allCollectors(collect.Bounds{})
	names := make([]string, 0, len(all))
	for _, c := range all {
		names = append(names, c.Source())
	}
	return names
}

// validateSources refuses a source name this build does not have.
//
// Silently ignoring a typo is the worse failure by far: `--without listner`
// would leave the probe RUNNING on a host whose owner believes they turned it
// off, and nothing in the output would say so.
func validateSources(disabled []string) error {
	known := sourceNames()
	for _, name := range disabled {
		if !slices.Contains(known, name) {
			return fmt.Errorf("unknown source %q: this agent collects %s", name, strings.Join(known, ", "))
		}
	}
	return nil
}

func collectors(cfg *state.Config, override, disabled []string) []collect.Collector {
	bounds := collect.Bounds{}
	var off []string
	if cfg != nil {
		bounds.Roots = cfg.ScanRoots
		bounds.MaxFileBytes = cfg.MaxFileBytes
		bounds.MaxDepth = cfg.MaxDepth
		off = cfg.DisabledSources
	}
	if len(override) > 0 {
		bounds.Roots = override
	}
	off = append(off, disabled...)

	all := allCollectors(bounds)
	out := make([]collect.Collector, 0, len(all))
	for _, c := range all {
		if !slices.Contains(off, c.Source()) {
			out = append(out, c)
		}
	}
	return out
}

func runCollectors(ctx context.Context, cfg *state.Config, override, disabled []string) []collect.Result {
	var out []collect.Result
	for _, c := range collectors(cfg, override, disabled) {
		out = append(out, c.Collect(ctx))
	}
	return out
}

func cmdScan(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print observations as JSON")
	scanRoots := rootsFlag(fs)
	skip := withoutFlag(fs)
	dir := stateFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := validateSources(*skip); err != nil {
		return err
	}

	// Scanning does not require enrolment — seeing what the agent WOULD report
	// before letting it report anything is the point of this command.
	var cfg *state.Config
	if store, err := state.Open(*dir); err == nil {
		cfg, _ = store.LoadConfig()
	}

	results := runCollectors(ctx, cfg, *scanRoots, *skip)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}

	total := 0
	for _, r := range results {
		total += len(r.Observations)
		for _, o := range r.Observations {
			key := "no key found"
			if o.PrivateKeyPresent {
				key = "key at " + o.PrivateKeyLocation
			}
			fmt.Printf("  %-9s %s (%s)\n", o.Source, o.Location, key)
		}
		for _, e := range r.Errors {
			fmt.Printf("  !         %s: %s\n", e.Location, e.Error)
		}
		if !r.Completed {
			fmt.Printf("  note      the %s collector did not finish; nothing it found will be marked absent\n", r.Source)
		}
	}
	fmt.Printf("\n%d certificate(s) found. Nothing was uploaded.\n", total)
	return nil
}

// ── run ──────────────────────────────────────────────────────────────────────

func cmdRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	once := fs.Bool("once", false, "do not wait for approval; exit if it is pending")
	scanRoots := rootsFlag(fs)
	skip := withoutFlag(fs)
	dir := stateFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := validateSources(*skip); err != nil {
		return err
	}

	store, err := state.Open(*dir)
	if err != nil {
		return err
	}
	cfg, err := store.LoadConfig()
	if err != nil {
		return err
	}
	key, err := store.LoadOrCreateKey()
	if err != nil {
		return err
	}
	fingerprint, err := state.Fingerprint(key)
	if err != nil {
		return err
	}

	client := transport.New(cfg.ServerURL, Version)
	signer := &transport.Signer{Key: key, Fingerprint: fingerprint}

	if err := authenticate(ctx, client, signer, *once); err != nil {
		return err
	}

	if checkin, err := client.Checkin(ctx); err == nil {
		// Reported, not enforced. The agent cannot fix the host's clock, and
		// refusing to run would turn a warning into an outage — but an operator
		// reading these logs after "my fleet stopped authenticating" should find
		// the answer here.
		if skew, ok := checkin.ClockSkew(); ok && (skew > time.Minute || skew < -time.Minute) {
			fmt.Fprintf(os.Stderr,
				"warning: this host's clock is %s from the server's; assertions fail past two minutes\n",
				skew.Round(time.Second))
		}
	}

	started := time.Now()
	results := runCollectors(ctx, cfg, *scanRoots, *skip)
	runID := fmt.Sprintf("%s-%d", fingerprint[:12], started.UTC().Unix())

	observed := 0
	for _, r := range results {
		observed += len(r.Observations)
	}

	resp, err := transport.Report(ctx, client, runID, started, results)
	last := &state.LastRun{
		RunID:      runID,
		FinishedAt: time.Now().UTC().Format(time.RFC3339),
		Observed:   observed,
	}
	if err != nil {
		last.Error = err.Error()
		_ = store.SaveLastRun(last)
		return err
	}
	last.Recorded, last.Rejected = resp.Recorded, resp.Rejected
	if err := store.SaveLastRun(last); err != nil {
		return err
	}

	fmt.Printf("Reported %d observation(s): %d recorded, %d rejected (run %s).\n",
		observed, resp.Recorded, resp.Rejected, resp.RunID)
	for _, e := range resp.Errors {
		fmt.Fprintf(os.Stderr, "  rejected: %s\n", e)
	}
	return nil
}

// authenticate waits out a pending approval rather than failing.
//
// Running the installer before anyone has clicked approve is the NORMAL case in
// an unattended rollout, not a mistake — so the default is to wait, and --once
// is there for a cron job that should not hold a process open.
func authenticate(ctx context.Context, client *transport.Client, signer *transport.Signer, once bool) error {
	for {
		err := client.Authenticate(ctx, signer)

		var pending *transport.ErrPendingApproval
		if errors.As(err, &pending) {
			if once {
				return err
			}
			fmt.Fprintf(os.Stderr, "waiting for approval; retrying in %s\n", pending.RetryAfter)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(pending.RetryAfter):
				continue
			}
		}
		return err
	}
}

// ── status ───────────────────────────────────────────────────────────────────

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	dir := stateFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := state.Open(*dir)
	if err != nil {
		return err
	}

	fmt.Printf("version   %s\nstate     %s\n", Version, store.Dir())

	cfg, err := store.LoadConfig()
	if errors.Is(err, state.ErrNotEnrolled) {
		fmt.Println("enrolled  no — run `dtp-agent enroll`")
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Printf("server    %s\naccount   %s\nagent id  %s\n", cfg.ServerURL, cfg.AccountID, cfg.AgentID)

	if key, err := store.LoadOrCreateKey(); err == nil {
		if fp, err := state.Fingerprint(key); err == nil {
			fmt.Printf("key       %s\n", fp)
		}
	}

	last, err := store.LoadLastRun()
	if err != nil {
		return err
	}
	if last == nil {
		fmt.Println("last run  never")
		return nil
	}
	fmt.Printf("last run  %s — %d found, %d recorded, %d rejected\n",
		last.FinishedAt, last.Observed, last.Recorded, last.Rejected)
	if last.Error != "" {
		fmt.Printf("          FAILED: %s\n", last.Error)
	}
	return nil
}

func hostFacts() map[string]string {
	hostname, _ := os.Hostname()
	return map[string]string{
		"hostname":      hostname,
		"machine_id":    machineID(),
		"os":            osName(),
		"os_version":    osVersion(),
		"arch":          archName(),
		"agent_version": Version,
	}
}
