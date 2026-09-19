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
	"strings"
	"syscall"

	"github.com/SSLcom/dtp-discovery-agent/internal/collect"
	"github.com/SSLcom/dtp-discovery-agent/internal/service"
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

  dtp-agent service
        Run under the Windows Service Control Manager, which starts this and
        keeps the schedule the systemd timer keeps on Linux. Not something to
        type: start it with "sc.exe start DTPAgent". Listed because an
        administrator reading the service's image path will come looking for it.
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
	case "service":
		err = cmdService(os.Args[2:])
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
// collect. Recorded at enrollment so the service unit needs no arguments, and
// accepted on scan/run so the effect can be seen before it is committed to.
func withoutFlag(fs *flag.FlagSet) *roots {
	r := &roots{}
	fs.Var(r, "without", "source not to collect: "+strings.Join(collect.Names(), ", ")+" (repeatable)")
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
	if err := collect.ValidateDisabled(*skip); err != nil {
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

// scanOptions turns what the agent was told — its stored config and this
// invocation's flags — into what the collectors are given.
func scanOptions(cfg *state.Config, override, disabled []string) collect.Options {
	opts := collect.Options{}
	if cfg != nil {
		opts.File.Roots = cfg.ScanRoots
		opts.File.MaxFileBytes = cfg.MaxFileBytes
		opts.File.MaxDepth = cfg.MaxDepth
		opts.Keystores.Roots = cfg.KeystoreRoots
		opts.ServerConfig.NginxConfigs = cfg.NginxConfigs
		opts.ServerConfig.ApacheConfigs = cfg.ApacheConfigs
		opts.Disabled = cfg.DisabledSources
	}
	if len(override) > 0 {
		opts.File.Roots = override
	}
	opts.Disabled = append(opts.Disabled, disabled...)
	return opts
}

func runCollectors(ctx context.Context, cfg *state.Config, override, disabled []string) []collect.Result {
	return collect.Run(ctx, scanOptions(cfg, override, disabled))
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

	if err := collect.ValidateDisabled(*skip); err != nil {
		return err
	}

	// Scanning does not require enrollment — seeing what the agent WOULD report
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
			fmt.Printf("  %-13s %s (%s)\n", o.Source, o.Location, key)
		}
		for _, e := range r.Errors {
			fmt.Printf("  %-13s %s: %s\n", "!", e.Location, e.Error)
		}
		// Only worth saying when the collector actually had something to
		// report. A source that found nothing AND said nothing did not "fail to
		// finish" in any sense a reader could act on — on Linux, os_store is
		// simply not a thing, and printing a warning about it on every scan
		// teaches people to ignore the warnings that matter.
		if !r.Completed && (len(r.Observations) > 0 || len(r.Errors) > 0) {
			fmt.Printf("  %-13s the %s collector did not finish; nothing it found will be marked absent\n", "note", r.Source)
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

	if err := collect.ValidateDisabled(*skip); err != nil {
		return err
	}

	return reportOnce(ctx, *dir, *scanRoots, *skip, *once, consoleReporter())
}

// ── service ──────────────────────────────────────────────────────────────────

func cmdService(args []string) error {
	fs := flag.NewFlagSet("service", flag.ExitOnError)
	dir := stateFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	return runService(*dir)
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
	if st := serviceState(); st != "" {
		fmt.Printf("service   %s\n", st)
	}
	// Only where something writes one. On Linux and macOS the journal and
	// launchd's log already have it, and pointing at a file that does not
	// exist is worse than pointing at nothing.
	if _, err := os.Stat(service.LogPath(store.Dir())); err == nil {
		fmt.Printf("log       %s\n", service.LogPath(store.Dir()))
	}

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
