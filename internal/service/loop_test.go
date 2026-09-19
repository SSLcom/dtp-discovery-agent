package service

import (
	"context"
	"errors"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"
)

// clock replaces time.After so a test can step an hourly schedule in
// microseconds.
//
// `asked` is BUFFERED, which matters. Made unbuffered it deadlocks every test:
// the loop blocks inside After, which is called before the select on
// ctx.Done(), so a cancelled context never reaches it and the loop can never
// be stopped. The loop is already held still by `fire` — it sits in that
// select until the test ticks — so the buffer costs nothing.
type clock struct {
	asked chan time.Duration
	fire  chan time.Time
}

func newClock() *clock {
	return &clock{asked: make(chan time.Duration, 64), fire: make(chan time.Time)}
}

func (c *clock) After(d time.Duration) <-chan time.Time {
	c.asked <- d
	return c.fire
}

// nextWait returns the delay the loop is currently sleeping for, failing the
// test rather than hanging forever if the loop is not sleeping at all.
func (c *clock) nextWait(t *testing.T) time.Duration {
	t.Helper()
	select {
	case d := <-c.asked:
		return d
	case <-time.After(2 * time.Second):
		t.Fatal("the loop never went to sleep")
		return 0
	}
}

func (c *clock) tick(t *testing.T) {
	t.Helper()
	select {
	case c.fire <- time.Now():
	case <-time.After(2 * time.Second):
		t.Fatal("the loop was not waiting on the clock")
	}
}

type recorder struct {
	mu    sync.Mutex
	lines []string
	runs  int
}

func (r *recorder) logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, format)
}

func (r *recorder) log() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.lines, "\n")
}

func (r *recorder) ran() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.runs
}

func testLoop(c *clock, rec *recorder) *Loop {
	l := New(rec.logf)
	l.Rand = rand.New(rand.NewSource(1))
	l.after = c.After
	return l
}

// start runs the loop in the background and returns a cancel plus a channel
// carrying its return value, so every test can assert how it ended.
func start(t *testing.T, l *Loop, enrolled func() bool, work func(context.Context) error) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	// Buffered, and paired with a separate `exited`: a test that reads the
	// return value itself would otherwise leave the cleanup blocked on a
	// channel nothing will ever send to again.
	done := make(chan error, 1)
	exited := make(chan struct{})
	go func() {
		done <- l.Run(ctx, enrolled, work)
		close(exited)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-exited:
		case <-time.After(2 * time.Second):
			t.Error("the loop did not stop")
		}
	})
	return cancel, done
}

// The Windows install order is install, start, THEN enroll — so the service is
// already running when a member first tells it who it belongs to, and it must
// notice promptly. A member who has just typed `dtp-agent enroll` and watches
// nothing happen for twenty minutes concludes the product is broken.
func TestScansAsSoonAsItIsEnrolled(t *testing.T) {
	c, rec := newClock(), &recorder{}
	l := testLoop(c, rec)

	var mu sync.Mutex
	enrolled := false
	scanned := make(chan struct{}, 1)

	start(t, l, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return enrolled
	}, func(context.Context) error {
		scanned <- struct{}{}
		return nil
	})

	// Not enrolled: the loop polls, and it polls at the SHORT cadence rather
	// than the fleet one.
	if got := c.nextWait(t); got != DefaultEnrollPoll {
		t.Fatalf("polled every %s while unenrolled, want %s", got, DefaultEnrollPoll)
	}

	mu.Lock()
	enrolled = true
	mu.Unlock()
	c.tick(t)

	select {
	case <-scanned:
	case <-time.After(2 * time.Second):
		t.Fatal("enrollment did not produce a scan")
	}

	if !strings.Contains(rec.log(), "dtp-agent enroll") {
		t.Errorf("nothing in the log tells the member what to do next:\n%s", rec.log())
	}
}

// The mirror case: a service that was ALREADY enrolled when it started is a
// machine that just booted, and it waits — for the boot, and for the jitter
// that stops a cloned fleet arriving at DTP on the same second.
func TestWaitsOutTheBootDelayWhenAlreadyEnrolled(t *testing.T) {
	c, rec := newClock(), &recorder{}
	l := testLoop(c, rec)

	start(t, l, func() bool { return true }, func(context.Context) error { return nil })

	wait := c.nextWait(t)
	if wait < DefaultFirstDelay || wait >= DefaultFirstDelay+DefaultJitter {
		t.Fatalf("first scan scheduled in %s, want [%s, %s)",
			wait, DefaultFirstDelay, DefaultFirstDelay+DefaultJitter)
	}
}

// The property the jitter exists for. Two hosts imaged from one template run
// the same binary with the same config; if their schedules agree, a 500-server
// estate is a thundering herd once an hour, forever.
func TestJitterSpreadsTheFleet(t *testing.T) {
	waits := map[time.Duration]int{}

	for seed := int64(0); seed < 20; seed++ {
		c, rec := newClock(), &recorder{}
		l := testLoop(c, rec)
		l.Rand = rand.New(rand.NewSource(seed))

		start(t, l, func() bool { return true }, func(context.Context) error { return nil })
		waits[c.nextWait(t)]++
	}

	if len(waits) < 15 {
		t.Fatalf("20 hosts produced only %d distinct schedules; the fleet is not being spread", len(waits))
	}
}

// A blip must not take a host out of the inventory for good. On Windows the
// service would stay stopped until somebody noticed, and nobody notices a host
// that has gone quiet — that is the exact failure the staleness reporting in
// DTP exists to catch, arriving as a self-inflicted wound.
func TestAFailedScanIsRetriedRatherThanFatal(t *testing.T) {
	c, rec := newClock(), &recorder{}
	l := testLoop(c, rec)

	calls := make(chan struct{}, 8)
	_, done := start(t, l, func() bool { return true }, func(context.Context) error {
		calls <- struct{}{}
		return errors.New("dtp unreachable")
	})

	for i := 1; i <= 3; i++ {
		c.nextWait(t)
		c.tick(t)
		select {
		case <-calls:
		case <-time.After(2 * time.Second):
			t.Fatalf("scanned %d time(s) across %d ticks; a failure is swallowing later runs", i-1, i)
		}
	}

	select {
	case err := <-done:
		t.Fatalf("the loop exited on a failed scan: %v", err)
	default:
	}
	if !strings.Contains(rec.log(), "scan failed") {
		t.Errorf("a failed scan left nothing in the log:\n%s", rec.log())
	}
}

// After a failure the loop must fall back to the FLEET cadence, not spin. An
// agent that retries a refused server every second is a denial of service
// aimed at DTP by five hundred of a customer's own machines.
func TestAFailedScanWaitsTheFullInterval(t *testing.T) {
	c, rec := newClock(), &recorder{}
	l := testLoop(c, rec)

	start(t, l, func() bool { return true }, func(context.Context) error {
		return errors.New("dtp unreachable")
	})

	c.nextWait(t) // the boot delay
	c.tick(t)

	wait := c.nextWait(t)
	if wait < DefaultInterval || wait >= DefaultInterval+DefaultJitter {
		t.Fatalf("retried in %s after a failure, want [%s, %s)",
			wait, DefaultInterval, DefaultInterval+DefaultJitter)
	}
}

// The Service Control Manager gives a service a bounded moment to stop and
// kills it if it overruns, so a stop must not wait out an hour-long sleep.
func TestStopWhileWaiting(t *testing.T) {
	c, rec := newClock(), &recorder{}
	l := testLoop(c, rec)

	cancel, done := start(t, l, func() bool { return true }, func(context.Context) error { return nil })
	c.nextWait(t)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("stopped with %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the loop did not stop while sleeping")
	}
}

// A stop that arrives mid-scan is the service shutting down, not the scan
// failing. Reporting it as a failure would put an error in the log of every
// host at every reboot, which teaches people to ignore the log.
func TestStopDuringAScanIsNotAFailure(t *testing.T) {
	c, rec := newClock(), &recorder{}
	l := testLoop(c, rec)

	scanning := make(chan struct{})
	cancel, done := start(t, l, func() bool { return true }, func(ctx context.Context) error {
		close(scanning)
		<-ctx.Done()
		return ctx.Err()
	})

	c.nextWait(t)
	c.tick(t)
	<-scanning
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("stopped with %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the loop did not stop during a scan")
	}

	if strings.Contains(rec.log(), "scan failed") {
		t.Errorf("shutting down was logged as a scan failure:\n%s", rec.log())
	}
}

// A service told to stop before its first tick must not get one scan in on the
// way out — on an unenrolled host the first wait is zero, so there is a path
// straight past the sleep into work.
func TestNoScanAfterAnImmediateStop(t *testing.T) {
	c, rec := newClock(), &recorder{}
	l := testLoop(c, rec)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var mu sync.Mutex
	ran := 0
	err := l.Run(ctx, func() bool { return true }, func(context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		ran++
		return nil
	})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("returned %v, want context.Canceled", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if ran != 0 {
		t.Fatalf("scanned %d time(s) after the context was already cancelled", ran)
	}
	_ = c
	_ = rec
}
