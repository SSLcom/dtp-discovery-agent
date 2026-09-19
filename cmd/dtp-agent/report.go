package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/SSLcom/dtp-discovery-agent/internal/state"
	"github.com/SSLcom/dtp-discovery-agent/internal/transport"
)

// reporter is where one run's account of itself goes.
//
// The command line splits it: results on stdout, warnings on stderr, so a
// member can pipe one without the other. A Windows service sends both to its
// log file, because a service started by the Service Control Manager has no
// terminal and anything written to either stream is discarded — which is why
// this is a parameter and not two calls to fmt.
type reporter struct {
	info func(format string, args ...any)
	warn func(format string, args ...any)
}

func consoleReporter() reporter {
	return reporter{
		info: func(format string, args ...any) { fmt.Printf(format+"\n", args...) },
		warn: func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) },
	}
}

// reportOnce is one complete cycle: authenticate, scan, upload, remember.
//
// SHARED BY `dtp-agent run` AND BY THE WINDOWS SERVICE, which must do exactly
// the same thing on its own schedule. A service that carried its own copy of
// this would be a second implementation of the product's entire job, running
// on the platform whose store collector finds the most and whose failures are
// the hardest to see — and it would drift, because only one of the two is
// exercised by anyone typing a command.
func reportOnce(ctx context.Context, dir string, override, disabled []string, once bool, out reporter) error {
	store, err := state.Open(dir)
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

	if err := authenticate(ctx, client, signer, once, out); err != nil {
		return err
	}

	if checkin, err := client.Checkin(ctx); err == nil {
		// Reported, not enforced. The agent cannot fix the host's clock, and
		// refusing to run would turn a warning into an outage — but an operator
		// reading these logs after "my fleet stopped authenticating" should find
		// the answer here.
		if skew, ok := checkin.ClockSkew(); ok && (skew > time.Minute || skew < -time.Minute) {
			out.warn("warning: this host's clock is %s from the server's; assertions fail past two minutes",
				skew.Round(time.Second))
		}
	}

	started := time.Now()
	results := runCollectors(ctx, cfg, override, disabled)
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

	out.info("Reported %d observation(s): %d recorded, %d rejected (run %s).",
		observed, resp.Recorded, resp.Rejected, resp.RunID)
	for _, e := range resp.Errors {
		out.warn("  rejected: %s", e)
	}
	return nil
}

// authenticate waits out a pending approval rather than failing.
//
// Running the installer before anyone has clicked approve is the NORMAL case in
// an unattended rollout, not a mistake — so the default is to wait, and --once
// is there for a cron job that should not hold a process open. The Windows
// service waits too: it is already resident, and coming back in an hour would
// mean an admin who approves an agent watches nothing happen for an hour.
func authenticate(ctx context.Context, client *transport.Client, signer *transport.Signer, once bool, out reporter) error {
	for {
		err := client.Authenticate(ctx, signer)

		var pending *transport.ErrPendingApproval
		if errors.As(err, &pending) {
			if once {
				return err
			}
			out.warn("waiting for approval; retrying in %s", pending.RetryAfter)
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
