package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogWritesTimestampedLines(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenLog(LogPath(dir), 0)
	if err != nil {
		t.Fatal(err)
	}
	l.Printf("reported %d observation(s)", 7)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(LogPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if !strings.Contains(got, "reported 7 observation(s)") {
		t.Fatalf("the line is not in the log: %q", got)
	}
	// A log of a service nobody was watching is only useful with times on it.
	if !strings.Contains(got, "T") || !strings.Contains(got, "Z") {
		t.Fatalf("no RFC3339 timestamp: %q", got)
	}
}

// The cap exists for a service stuck in a failure it reports every minute.
// Without rotation that is a file that grows without bound on a customer's
// machine, and they find it before we do.
func TestLogRotatesAtTheCap(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenLog(LogPath(dir), 256)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		l.Printf("scan failed: dtp unreachable (%d)", i)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(LogPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > 512 {
		t.Fatalf("the live log is %d bytes against a 256-byte cap; it is not rotating", fi.Size())
	}

	// Exactly one previous file, and it must hold the OLDER lines — rotation
	// that threw away what just happened would delete the description of the
	// failure at the moment the failure filled the log.
	if _, err := os.Stat(LogPath(dir) + ".old"); err != nil {
		t.Fatalf("no rotated file: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected the log and one rotation, got %v", names)
	}
}

// Reopening must not lose what the last run wrote: on Windows this is the only
// record of why a service stopped reporting, and a restart is exactly when
// somebody goes looking for it.
func TestLogAppendsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	for _, line := range []string{"first boot", "second boot"} {
		l, err := OpenLog(LogPath(dir), 0)
		if err != nil {
			t.Fatal(err)
		}
		l.Printf("%s", line)
		l.Close()
	}

	raw, _ := os.ReadFile(LogPath(dir))
	for _, want := range []string{"first boot", "second boot"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("%q missing after a restart: %q", want, raw)
		}
	}
}

// A full disk or a revoked permission must cost the log, not the scan.
func TestPrintfOnAClosedLogIsHarmless(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenLog(LogPath(dir), 0)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	l.Printf("this goes nowhere and must not panic")
}

func TestLogPathIsInTheStateDirectory(t *testing.T) {
	if got, want := LogPath("/var/lib/dtp-agent"), filepath.Join("/var/lib/dtp-agent", "agent.log"); got != want {
		t.Fatalf("LogPath = %q, want %q", got, want)
	}
}

// THE CASE THAT MADE THIS NECESSARY. A host installed but not yet enrolled says
// so every minute; a host waiting for approval says so every thirty seconds.
// Both are the normal state during a rollout and neither is an error, and
// either one fills the log in days — rotating away the lines that say which
// agent this is, which is what somebody opening the log came to read.
func TestARepeatedLineDoesNotFillTheLog(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenLog(LogPath(dir), 0)
	if err != nil {
		t.Fatal(err)
	}

	clock := time.Now()
	l.now = func() time.Time { return clock }

	// A day of minute-by-minute polling.
	for i := 0; i < 1440; i++ {
		l.Printf("not enrolled yet — run `dtp-agent enroll`; checking again in %s", time.Minute)
		clock = clock.Add(time.Minute)
	}
	l.Close()

	raw, err := os.ReadFile(LogPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Count(string(raw), "\n")

	// One every half hour, not one a minute.
	if lines > 60 {
		t.Fatalf("a day of polling wrote %d lines; the log would rotate itself away", lines)
	}
	// But it must still be there, repeatedly: a log whose last line is half an
	// hour old cannot be told from a service that died half an hour ago.
	if lines < 24 {
		t.Fatalf("a day of polling wrote only %d lines; the agent looks dead between them", lines)
	}
	if !strings.Contains(string(raw), "and 29 more like it") {
		t.Fatalf("the suppressed repeats are not accounted for:\n%s", raw)
	}
}

// Collapsing must never hide a CHANGE. The line a reader needs is almost always
// the one that is different from the line before it.
func TestADifferentLineIsNeverSuppressed(t *testing.T) {
	dir := t.TempDir()
	l, _ := OpenLog(LogPath(dir), 0)
	clock := time.Now()
	l.now = func() time.Time { return clock }

	for i := 0; i < 10; i++ {
		l.Printf("not enrolled yet")
		clock = clock.Add(time.Minute)
	}
	l.Printf("scan failed: dtp unreachable")
	l.Printf("Reported 7 observation(s): 7 recorded, 0 rejected (run abc).")
	l.Close()

	raw, _ := os.ReadFile(LogPath(dir))
	for _, want := range []string{"scan failed: dtp unreachable", "Reported 7 observation(s)"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("%q was suppressed:\n%s", want, raw)
		}
	}
	// The repeats it stood in for are reported on the line that breaks the run.
	if !strings.Contains(string(raw), "(and 9 more like it)") {
		t.Fatalf("the run of repeats was not accounted for:\n%s", raw)
	}
}

// A service stopped while waiting must not take the count of how long it waited
// with it.
func TestClosingAccountsForWhatWasSuppressed(t *testing.T) {
	dir := t.TempDir()
	l, _ := OpenLog(LogPath(dir), 0)
	clock := time.Now()
	l.now = func() time.Time { return clock }

	for i := 0; i < 5; i++ {
		l.Printf("waiting for approval; retrying in 30s")
		clock = clock.Add(30 * time.Second)
	}
	l.Close()

	raw, _ := os.ReadFile(LogPath(dir))
	if !strings.Contains(string(raw), "4 more times") {
		t.Fatalf("closing left the suppressed repeats unaccounted for:\n%s", raw)
	}
}
