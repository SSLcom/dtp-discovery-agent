// Package state owns everything the agent keeps on disk: its keypair, its
// configuration, and what it remembers between runs.
//
// THE KEYPAIR IS THE AGENT'S IDENTITY AND NEVER LEAVES THIS MACHINE. DTP holds
// only the public half and verifies a signature over each assertion, so there
// is no shared secret to leak and revoking an agent is a status flip on the
// server rather than a rotation here. That property is only true if the private
// half stays put, which is why this package is the one place that touches it and
// why nothing in it returns key bytes.
package state

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Permissions. The directory is owner-only too: a world-readable directory
// containing a 0600 key still tells an attacker exactly what to come back for.
const (
	dirPerm  = 0o700
	keyPerm  = 0o600
	filePerm = 0o600
)

// Config is what the agent was told, and what it learned when it enrolled.
// Written on `enroll`, read by everything else.
type Config struct {
	ServerURL string `json:"server_url"`
	AccountID string `json:"account_id"`

	// Assigned by DTP at registration. Not authority — the signed fingerprint
	// is — but useful in logs and in a support conversation.
	AgentID        string `json:"agent_id,omitempty"`
	RegistrationID string `json:"registration_id,omitempty"`

	// Scan bounds. Zero means "use the default"; see collect.Bounds.
	ScanRoots    []string `json:"scan_roots,omitempty"`
	MaxFileBytes int64    `json:"max_file_bytes,omitempty"`
	MaxDepth     int      `json:"max_depth,omitempty"`
}

// Store is the agent's state directory.
type Store struct{ dir string }

// DefaultDir is where the agent keeps its state, per platform. A member can
// override it; these are what the packages install.
func DefaultDir() string {
	switch runtime.GOOS {
	case "windows":
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "DTP", "agent")
		}
		return filepath.Join("C:\\", "ProgramData", "DTP", "agent")
	case "darwin":
		return "/Library/Application Support/DTP/agent"
	default:
		return "/var/lib/dtp-agent"
	}
}

func Open(dir string) (*Store, error) {
	if dir == "" {
		dir = DefaultDir()
	}
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("state directory %s: %w", dir, err)
	}
	// MkdirAll does NOT change the mode of a directory that already exists, so
	// a state directory a package or an operator created as 0755 would keep
	// this agent's private key world-readable forever. Tightened on every open
	// rather than only at creation, because the directory outlives any one
	// version of this binary.
	if err := secure(dir, dirPerm); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) Dir() string { return s.dir }

func (s *Store) path(name string) string { return filepath.Join(s.dir, name) }

// ── keypair ──────────────────────────────────────────────────────────────────

// LoadOrCreateKey returns this agent's private key, generating one on first run.
//
// P-256: universally available, small signatures, and — the deciding reason —
// supported by every platform key store the agent may later be asked to hold it
// in. The server derives the algorithm from the key it stored, never from the
// request, so changing this later is a per-agent decision rather than a
// protocol break.
func (s *Store) LoadOrCreateKey() (*ecdsa.PrivateKey, error) {
	path := s.path("agent.key")

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		// TIGHTENED ON EVERY LOAD, not only at creation. A key restored from a
		// backup, laid down by a configuration-management tool, or written by
		// an older version of this binary arrives with whatever mode it
		// arrives with — and the agent would go on using it, re-securing the
		// directory around it, while the private key itself stayed
		// world-readable. Same reasoning as the directory in Open; the file
		// needs it for the same reason.
		if err := secure(path, keyPerm); err != nil {
			return nil, err
		}
		return parseKey(raw)
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	// Written 0600 by WriteFile's mode AND by an explicit Chmod: the process
	// umask can only clear bits, but an existing file's mode survives a write,
	// so a key file left group-readable by an older version stays that way
	// unless it is corrected here.
	if err := os.WriteFile(path, encoded, keyPerm); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	if err := secure(path, keyPerm); err != nil {
		return nil, err
	}
	return key, nil
}

// secure narrows a path's permissions to exactly `want`, and says which path it
// was if it cannot. Only ever tightens — the modes it is called with are the
// tightest the agent uses.
//
// ON WINDOWS THIS IS ALL BUT A NO-OP, and that is not a gap being hidden:
// os.Chmod there controls only the read-only attribute, and access is decided
// by the ACL. The call is harmless and the guarantee simply is not a POSIX mode
// on that platform — which is also why fileOwner reports nothing there.
func secure(path string, want os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Mode().Perm() == want {
		return nil
	}
	if err := os.Chmod(path, want); err != nil {
		return fmt.Errorf("securing %s: %w", path, err)
	}
	return nil
}

func parseKey(raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("agent.key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse agent.key: %w", err)
	}
	return key, nil
}

// PublicKeyPEM is the half that goes to DTP — the ONLY half that ever does.
func PublicKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// Fingerprint is how DTP names this agent: SHA-256 over the DER of the public
// key. Computed from the KEY, not from the PEM text, so re-encoding or stray
// whitespace cannot produce a second identity for one keypair — the server
// computes it the same way for the same reason.
func Fingerprint(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// ── config ───────────────────────────────────────────────────────────────────

func (s *Store) LoadConfig() (*Config, error) {
	raw, err := os.ReadFile(s.path("config.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotEnrolled
		}
		return nil, err
	}
	cfg := &Config{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse config.json: %w", err)
	}
	return cfg, nil
}

func (s *Store) SaveConfig(cfg *Config) error {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return s.writeAtomic("config.json", append(raw, '\n'))
}

// ErrNotEnrolled is what every command other than `enroll` reports when the
// agent has no config — a first-run state, not a failure, and worth its own
// error so the CLI can say "run enroll" instead of printing a path.
var ErrNotEnrolled = errors.New("this agent is not enrolled: run `dtp-agent enroll` first")

// ── last-run memory ──────────────────────────────────────────────────────────

// LastRun is what the agent remembers about its previous scan.
type LastRun struct {
	RunID      string `json:"run_id"`
	FinishedAt string `json:"finished_at"`
	Observed   int    `json:"observed"`
	Recorded   int    `json:"recorded"`
	Rejected   int    `json:"rejected"`
	Error      string `json:"error,omitempty"`
}

func (s *Store) LoadLastRun() (*LastRun, error) {
	raw, err := os.ReadFile(s.path("last-run.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	run := &LastRun{}
	if err := json.Unmarshal(raw, run); err != nil {
		return nil, fmt.Errorf("parse last-run.json: %w", err)
	}
	return run, nil
}

func (s *Store) SaveLastRun(run *LastRun) error {
	raw, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return err
	}
	return s.writeAtomic("last-run.json", append(raw, '\n'))
}

// writeAtomic replaces a file via a temp file and a rename, so a crash or a
// full disk leaves the previous contents rather than a half-written file the
// next run cannot parse. Agents run unattended on machines nobody logs into;
// self-inflicted corruption is not recoverable by a human noticing.
func (s *Store) writeAtomic(name string, data []byte) error {
	tmp, err := os.CreateTemp(s.dir, "."+name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(filePerm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path(name))
}
