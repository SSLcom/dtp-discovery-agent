package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyIsGeneratedOnceAndReused(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	first, err := store.LoadOrCreateKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.LoadOrCreateKey()
	if err != nil {
		t.Fatal(err)
	}

	// The key IS the agent's identity. Regenerating it would silently create a
	// second agent that has to be approved all over again, while the first went
	// quiet and started looking stale.
	if !first.Equal(second) {
		t.Fatal("the key was regenerated; the agent's identity must survive a restart")
	}
}

func TestKeyIsWrittenOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	store, _ := Open(dir)
	if _, err := store.LoadOrCreateKey(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir, "agent.key"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("agent.key mode = %o, want 600", perm)
	}

	// A world-readable DIRECTORY holding a 0600 key still tells an attacker
	// exactly what to come back for.
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("state directory mode = %o, want owner-only", perm)
	}
}

// Only the public half is ever rendered for transmission.
func TestPublicKeyPEMCarriesNoPrivateMaterial(t *testing.T) {
	store, _ := Open(t.TempDir())
	key, err := store.LoadOrCreateKey()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := PublicKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pub, "BEGIN PUBLIC KEY") {
		t.Fatalf("not a public key block: %q", pub)
	}
	if strings.Contains(pub, "PRIVATE") {
		t.Fatal("private key material in what is sent to DTP")
	}
}

// Computed from the key's DER, exactly as the server computes it — so a
// re-encode or stray whitespace cannot produce a second identity for one pair.
func TestFingerprintIsStable(t *testing.T) {
	store, _ := Open(t.TempDir())
	key, _ := store.LoadOrCreateKey()

	first, err := Fingerprint(key)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := Fingerprint(key)

	if first != second {
		t.Fatal("fingerprint is not stable for one key")
	}
	if len(first) != 64 {
		t.Errorf("fingerprint = %q, want 64 hex characters", first)
	}
}

func TestUnenrolledStateSaysSoPlainly(t *testing.T) {
	store, _ := Open(t.TempDir())
	if _, err := store.LoadConfig(); err != ErrNotEnrolled {
		t.Fatalf("want ErrNotEnrolled, got %v", err)
	}
}

func TestConfigRoundTrips(t *testing.T) {
	dir := t.TempDir()
	store, _ := Open(dir)

	want := &Config{ServerURL: "https://dtp.example.com", AccountID: "acct-1", AgentID: "agent-1"}
	if err := store.SaveConfig(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerURL != want.ServerURL || got.AccountID != want.AccountID || got.AgentID != want.AgentID {
		t.Errorf("config round-trip lost data: %+v", got)
	}
}

// An agent runs unattended on a machine nobody logs into, so a half-written
// file is not something a human notices and fixes.
func TestWritesAreAtomicAndLeaveNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	store, _ := Open(dir)

	if err := store.SaveLastRun(&LastRun{RunID: "r1", Observed: 3}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveLastRun(&LastRun{RunID: "r2", Observed: 4}); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("left a temp file behind: %s", e.Name())
		}
	}

	last, err := store.LoadLastRun()
	if err != nil {
		t.Fatal(err)
	}
	if last.RunID != "r2" {
		t.Errorf("last run = %q, want the most recent", last.RunID)
	}
}

func TestNoLastRunIsNotAnError(t *testing.T) {
	store, _ := Open(t.TempDir())
	last, err := store.LoadLastRun()
	if err != nil {
		t.Fatal(err)
	}
	if last != nil {
		t.Errorf("want nil for an agent that has never run, got %+v", last)
	}
}
