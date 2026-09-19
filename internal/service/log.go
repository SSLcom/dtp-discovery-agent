package service

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultLogBytes is where the log is rotated. A service writing a handful of
// lines an hour takes years to reach it; a service stuck in a failure it
// reports every minute reaches it in weeks, and that is the one this cap is
// for.
const DefaultLogBytes = 1 << 20

// DefaultRepeatWindow is how long one message is allowed to stand for itself
// before it is written again.
//
// WITHOUT THIS THE LOG EATS ITSELF IN THE COMMONEST CASE THERE IS. A host that
// has been installed but not yet enrolled says so every minute; a host waiting
// for an admin to approve it says so every thirty seconds. Neither is an
// error, both are the normal state during a rollout, and either fills a
// megabyte in a few days — rotating away the startup lines that say which agent
// this is, which is exactly what somebody arriving at the log went there to
// read.
//
// Repeats are not silently dropped, because a log whose last line is half an
// hour old cannot be told from a service that died half an hour ago. The
// message is written again on the window, carrying the count of what it stood
// in for: forty-eight lines a day instead of fourteen hundred, and the reader
// can still see the agent is alive.
const DefaultRepeatWindow = 30 * time.Minute

// Log is the agent's record of what it did while nobody was watching.
//
// WHY A FILE AT ALL. A Windows service has no terminal: anything the agent
// writes to stdout or stderr under the Service Control Manager goes nowhere, so
// every line the Linux packages send to the journal would simply be lost. The
// first support question about this agent is "is it working", and on Windows
// `dtp-agent status` plus this file are the entire answer.
//
// WHY NOT THE WINDOWS EVENT LOG, which is the idiomatic place. Writing there
// needs a registered event source, which is a registry key an elevated process
// has to install — so the log would exist only when an install step had
// succeeded, and the case where you most want a log is the case where
// installation went wrong. A file the agent opens itself is always there.
//
// It lives in the state directory, which the agent has already locked to itself,
// SYSTEM and the administrators. Nothing secret goes in it — paths, hostnames
// and counts — but it names every certificate location on the host, which is a
// map worth not handing out.
type Log struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	n    int64

	// RepeatWindow may be changed before the first write. Zero means
	// DefaultRepeatWindow; negative disables collapsing entirely.
	RepeatWindow time.Duration

	last       string
	lastAt     time.Time
	suppressed int

	// now is swapped out by tests. A repeat window that could only be
	// exercised by waiting half an hour is one no test would ever check.
	now func() time.Time
}

// OpenLog appends to path, rotating first if it is already at the cap.
func OpenLog(path string, max int64) (*Log, error) {
	if max <= 0 {
		max = DefaultLogBytes
	}
	l := &Log{path: path, max: max, RepeatWindow: DefaultRepeatWindow, now: time.Now}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Log) open() error {
	if fi, err := os.Stat(l.path); err == nil && fi.Size() >= l.max {
		if err := l.rotate(); err != nil {
			return err
		}
	}
	// 0600: see the type comment. On Windows the mode is advisory and the
	// directory's ACL is what actually holds, which is why this file lives in
	// the state directory rather than somewhere more discoverable.
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open log %s: %w", l.path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.f, l.n = f, fi.Size()
	return nil
}

// rotate keeps exactly ONE previous file. Keeping several would need pruning,
// and a log that grows without bound on a customer's machine is a bug the
// customer finds first; keeping none would throw away the lines describing the
// failure at the moment the failure filled the log.
func (l *Log) rotate() error {
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
	old := l.path + ".old"
	if err := os.Remove(old); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(l.path, old); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Printf writes one timestamped line.
//
// IT NEVER RETURNS AN ERROR AND NEVER PANICS. This is the logger for an
// unattended service: a full disk or a revoked permission must cost the log,
// not the scan. A member whose portfolio quietly stopped updating because the
// agent could not write a log file would have no way at all to find out why.
func (l *Log) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	msg := fmt.Sprintf(format, args...)
	now := l.clock()

	if l.RepeatWindow >= 0 && msg == l.last && now.Sub(l.lastAt) < l.window() {
		l.suppressed++
		return
	}

	suffix := ""
	if l.suppressed > 0 {
		// Said on the line it belongs to rather than on one of its own, so a
		// reader scanning for the last thing that happened sees both at once.
		suffix = fmt.Sprintf(" (and %d more like it)", l.suppressed)
		l.suppressed = 0
	}
	l.last, l.lastAt = msg, now
	l.writeLocked(now, msg+suffix)
}

func (l *Log) writeLocked(now time.Time, msg string) {
	if l.f == nil {
		return
	}
	n, err := l.f.WriteString(fmt.Sprintf("%s %s\n", now.UTC().Format(time.RFC3339), msg))
	l.n += int64(n)
	if err != nil {
		return
	}
	if l.n >= l.max {
		if err := l.rotate(); err != nil {
			return
		}
		_ = l.open()
	}
}

func (l *Log) window() time.Duration {
	if l.RepeatWindow == 0 {
		return DefaultRepeatWindow
	}
	return l.RepeatWindow
}

func (l *Log) clock() time.Time {
	if l.now == nil {
		return time.Now()
	}
	return l.now()
}

func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Anything still standing behind a repeated line is written out here, so a
	// service that stopped while waiting does not take the count of how long it
	// waited with it.
	if l.suppressed > 0 && l.f != nil {
		n := l.suppressed
		l.suppressed = 0
		l.writeLocked(l.clock(), fmt.Sprintf("(the line above happened %d more times)", n))
	}
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// LogPath is where the service writes, given a state directory. One function so
// the service and `dtp-agent status` cannot disagree about it — a status
// command that points at the wrong file is worse than one that points at none.
func LogPath(stateDir string) string { return filepath.Join(stateDir, "agent.log") }
