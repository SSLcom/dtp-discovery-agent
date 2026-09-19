package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
