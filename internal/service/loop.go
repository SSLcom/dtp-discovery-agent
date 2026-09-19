// Package service keeps the agent's schedule on a platform whose service
// manager does not keep one for it.
//
// On Linux a systemd timer decides when the agent runs and the agent is a
// oneshot that exits; launchd does the same on macOS with StartInterval. The
// Windows Service Control Manager has no equivalent — it starts a process and
// expects it to stay up — so on Windows the agent holds its own schedule, and
// this is where that schedule lives.
//
// THE CADENCE IS COPIED FROM packaging/systemd/dtp-agent.timer ON PURPOSE.
// Reporting rhythm is a property of the fleet, not of the operating system: an
// estate whose Linux half refreshes hourly and whose Windows half refreshes
// daily has a portfolio that is confidently wrong about exactly the hosts
// nobody is looking at. When one of these numbers changes, the other has to.
//
// It is a separate package from the Windows glue because it is where the
// judgement is, and a scheduler that can only be exercised on the platform it
// ships to is a scheduler nobody tests. Everything here is portable and runs
// under `go test` on any host.
package service

import (
	"context"
	"math/rand"
	"time"
)

const (
	// Hourly, matching the timer. The agent's own detail page in DTP calls a
	// host stale after 24 hours, so the cadence has to sit well inside that.
	DefaultInterval = time.Hour

	// SPREAD THE FLEET. Without this every machine cloned from one image
	// reports on the same second of the same minute, and a 500-server estate
	// arrives at DTP as a thundering herd once an hour, forever. It is the
	// mirror of RandomizedDelaySec.
	DefaultJitter = 15 * time.Minute

	// The mirror of OnBootSec: a service set to start automatically starts
	// while the machine is still bringing itself up, and a disk walk is not
	// what that moment needs.
	DefaultFirstDelay = 5 * time.Minute

	// How often to look again while the agent has not been enrolled. Short,
	// because this is not a fleet cadence — it is a person at a console who
	// has just run `dtp-agent enroll` and is waiting to see something happen.
	DefaultEnrollPoll = time.Minute
)

// Loop runs work on a schedule until its context is cancelled.
//
// The zero value is not useful; use New.
type Loop struct {
	Interval   time.Duration
	Jitter     time.Duration
	FirstDelay time.Duration
	EnrollPoll time.Duration
	Rand       *rand.Rand
	Logf       func(format string, args ...any)

	// after exists so tests can drive the clock. Production leaves it nil and
	// gets time.After; a test that had to wait out a real hour would be a test
	// nobody runs, which is the same as not having one.
	after func(time.Duration) <-chan time.Time
}

// New returns a Loop with the shipped cadence.
func New(logf func(string, ...any)) *Loop {
	return &Loop{
		Interval:   DefaultInterval,
		Jitter:     DefaultJitter,
		FirstDelay: DefaultFirstDelay,
		EnrollPoll: DefaultEnrollPoll,
		Rand:       rand.New(rand.NewSource(time.Now().UnixNano())),
		Logf:       logf,
	}
}

// Run blocks until ctx is cancelled, calling work on the schedule.
//
// `enrolled` reports whether the agent has been given a server and an account
// yet. It is asked before every run rather than once at startup, because the
// normal Windows install order is install, start, THEN enroll: the service is
// already running when a member first tells it who it belongs to.
//
// THE FIRST RUN IS IMMEDIATE IF THE AGENT WAS NOT ENROLLED WHEN THE SERVICE
// STARTED, and delayed if it was. Those are two different situations wearing
// the same clothes. An agent that becomes enrolled while this loop is running
// has a person watching it, and making them wait out a boot delay plus up to
// fifteen minutes of fleet jitter to find out whether enrollment worked is the
// difference between a product that feels installed and one that feels broken.
// An agent that was already enrolled when the service started is a machine that
// just booted, and it gets the full delay, because that is the case the jitter
// exists for.
//
// Run returns ctx.Err() and nothing else: a failure inside work is logged and
// retried on the next tick, never fatal. A service that exits because DTP was
// briefly unreachable is a host that stops reporting for good over a blip, and
// on Windows it would stay stopped until somebody noticed.
func (l *Loop) Run(ctx context.Context, enrolled func() bool, work func(context.Context) error) error {
	wait := time.Duration(0)
	if enrolled() {
		wait = l.FirstDelay + l.jitter()
		l.logf("first scan in %s", wait.Round(time.Second))
	}

	for {
		if err := l.sleep(ctx, wait); err != nil {
			return err
		}

		if !enrolled() {
			// Said at every poll rather than once. This is the one line in the
			// log that tells a member the install succeeded and the next move
			// is theirs, and the person who goes looking for it is the person
			// who came back an hour later.
			l.logf("not enrolled yet — run `dtp-agent enroll`; checking again in %s", l.EnrollPoll)
			wait = l.EnrollPoll
			continue
		}

		if err := work(ctx); err != nil {
			// ctx cancellation arrives here as an error from work, not as a
			// reason to log a failure: the service is stopping, which is not
			// something going wrong.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			l.logf("scan failed: %v", err)
		}

		wait = l.Interval + l.jitter()
		l.logf("next scan in %s", wait.Round(time.Second))
	}
}

func (l *Loop) sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		// Still honour a cancelled context: a service told to stop before its
		// first tick must not get one run in on the way out.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}

	after := l.after
	if after == nil {
		after = time.After
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-after(d):
		return nil
	}
}

func (l *Loop) jitter() time.Duration {
	if l.Jitter <= 0 || l.Rand == nil {
		return 0
	}
	return time.Duration(l.Rand.Int63n(int64(l.Jitter)))
}

func (l *Loop) logf(format string, args ...any) {
	if l.Logf == nil {
		return
	}
	l.Logf(format, args...)
}
