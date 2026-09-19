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
}

// OpenLog appends to path, rotating first if it is already at the cap.
func OpenLog(path string, max int64) (*Log, error) {
	if max <= 0 {
		max = DefaultLogBytes
	}
	l := &Log{path: path, max: max}
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

	if l.f == nil {
		return
	}
	line := fmt.Sprintf("%s %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
	n, err := l.f.WriteString(line)
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

func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
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
