package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// THE ONE THING IN THE STATE DIRECTORY ANY LOCAL USER MAY READ.
//
// The Windows notification-area icon runs as whoever is signed in, unelevated —
// and under UAC that is true even of an administrator, whose filtered token
// carries Administrators as deny-only. The state directory is closed to all of
// them, as it must be: it holds the agent's private key. So the service
// publishes a small summary of what it is doing, and this is it.
//
// IT LIVES INSIDE THE PROTECTED DIRECTORY, NOT BESIDE IT, and that is the
// security decision in this file. %ProgramData% lets any local user create a
// folder, so a status directory next to the state directory could be created
// first by an unprivileged user — who would then own it, and could swap it for
// a junction to anywhere on the disk, and the service, running as SYSTEM, would
// write its file wherever that pointed. Nested here, nobody but SYSTEM and the
// administrators can create, replace or redirect it. A reader needs no access
// to the parent at all: Windows grants every user "bypass traverse checking",
// so a file whose own ACL allows a read can be opened by its full path through
// a directory the reader cannot list.
//
// WHAT IS IN IT IS CHOSEN TO BE HARMLESS TO SHOW EVERY USER OF THE MACHINE:
// what the agent is doing, when it last reported and how much it found, the
// last error, and the DTP address it reports to. Not the key, not the account
// id, not the agent id, not the fingerprint — none of which a person looking at
// an icon needs, and all of which belong to the administrator's `status`.
const publicDirName = "public"

// Phases, as the service reports them.
const (
	// Installed and running, with nobody having run `dtp-agent enroll`.
	PhaseNotEnrolled = "not_enrolled"
	// Enrolled; an account admin has not admitted it yet.
	PhasePending = "pending"
	// Enrolled; the first scan has not run yet. The service waits out a boot
	// delay first, so this lasts minutes after every restart.
	PhaseScheduled = "scheduled"
	// A scan is in progress.
	PhaseScanning = "scanning"
	// The last cycle reported successfully.
	PhaseReporting = "reporting"
	// The last cycle failed; LastError says why.
	PhaseFailed = "failed"
)

// PublicStatus is the summary the service publishes for the notification-area
// icon. Every field is safe for any local user to read; see above.
type PublicStatus struct {
	Version   string `json:"version"`
	UpdatedAt string `json:"updated_at"`
	Phase     string `json:"phase"`
	ServerURL string `json:"server_url,omitempty"`

	// The last scan that reached the upload step, successful or not.
	LastRunAt string `json:"last_run_at,omitempty"`
	Observed  int    `json:"observed"`
	Recorded  int    `json:"recorded"`
	Rejected  int    `json:"rejected"`

	LastError string `json:"last_error,omitempty"`
}

// PublicStatusPath is where the summary for a state directory is published.
// The icon finds it from DefaultDir; nothing configures it.
func PublicStatusPath(stateDir string) string {
	return filepath.Join(stateDir, publicDirName, "status.json")
}

// WritePublicStatus publishes the summary. A method on Store, not a function of
// a path, so that it can only be reached through Open — which is what has
// already closed the parent directory around it.
func (s *Store) WritePublicStatus(st *PublicStatus) error {
	dir := filepath.Join(s.dir, publicDirName)
	// A junction here would have SYSTEM write the file, and set the ACL below,
	// wherever it pointed. Only an administrator could have made one inside a
	// directory trustDir accepted — but the cost of not following it is one
	// rmdir, and the cost of following it is the ACL of an arbitrary folder.
	// os.Remove on a junction removes the link, never what it points at.
	if isReparse(dir) {
		if err := os.Remove(dir); err != nil {
			return fmt.Errorf("public status directory %s is a link and could not be removed: %w", dir, err)
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("public status directory %s: %w", dir, err)
	}
	// Reapplied on every write, as secure() is on every Open: the directory
	// outlives any one version of this binary, and the ACL is what the file's
	// whole safety rests on.
	if err := secureReadable(dir); err != nil {
		return err
	}

	if st.UpdatedAt == "" {
		st.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	// Temp files a stop interrupted between create and rename would otherwise
	// collect here for ever, one per unlucky shutdown.
	if stale, _ := filepath.Glob(filepath.Join(dir, ".status.json.*")); len(stale) > 0 {
		for _, f := range stale {
			if fi, err := os.Stat(f); err == nil && time.Since(fi.ModTime()) > time.Minute {
				_ = os.Remove(f)
			}
		}
	}

	tmp, err := os.CreateTemp(dir, ".status.json.*")
	if err != nil {
		return err
	}
	// CreateTemp makes it 0600; this file exists to be read by others. On
	// Windows the mode is meaningless and the directory's ACL decides.
	_ = tmp.Chmod(0o644)
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// ONE RETRY, because on Windows a rename over a file another process has
	// open fails, and the icon reads this file every few seconds. A collision
	// costs one stale reading, never a broken one: the old file stays whole.
	dest := PublicStatusPath(s.dir)
	if err := os.Rename(tmp.Name(), dest); err != nil {
		time.Sleep(100 * time.Millisecond)
		if err := os.Rename(tmp.Name(), dest); err != nil {
			// The cause alone, not the LinkError: that names the random temp
			// file, so two identical failures would never read as a repeat.
			var le *os.LinkError
			if errors.As(err, &le) {
				err = le.Err
			}
			return fmt.Errorf("publishing %s: %w", dest, err)
		}
	}
	return nil
}

// ReadPublicStatus reads a published summary. A missing file is (nil, nil):
// a service from before the icon existed, or one that has not started yet.
func ReadPublicStatus(stateDir string) (*PublicStatus, error) {
	raw, err := os.ReadFile(PublicStatusPath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	st := &PublicStatus{}
	if err := json.Unmarshal(raw, st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", PublicStatusPath(stateDir), err)
	}
	return st, nil
}
