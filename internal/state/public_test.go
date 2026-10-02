package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestPublicStatusRoundTrips(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	want := &PublicStatus{
		Version: "1.2.3", Phase: PhaseReporting, ServerURL: "https://dtp.example",
		LastRunAt: "2026-10-01T10:42:00Z", Observed: 12, Recorded: 11, Rejected: 1,
	}
	if err := store.WritePublicStatus(want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPublicStatus(store.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Phase != want.Phase || got.Observed != 12 || got.ServerURL != want.ServerURL {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if got.UpdatedAt == "" {
		t.Error("a status with no time on it cannot be told from one written last year")
	}
}

// A service from before the icon existed publishes nothing. That is a state
// to describe, not an error to show.
func TestNoPublicStatusIsNotAnError(t *testing.T) {
	got, err := ReadPublicStatus(t.TempDir())
	if err != nil || got != nil {
		t.Fatalf("got %+v, %v; want nil, nil", got, err)
	}
}

func TestPublishingLeavesNoTempFiles(t *testing.T) {
	store, _ := Open(t.TempDir())
	for _, phase := range []string{PhaseScanning, PhaseReporting} {
		if err := store.WritePublicStatus(&PublicStatus{Phase: phase}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(PublicStatusPath(store.Dir())))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("left a temp file behind: %s", e.Name())
		}
	}
}

// EVERY LOCAL USER CAN READ THIS FILE, so what goes into it is a decision, not
// a convenience. Adding a field turns this red on purpose: whoever adds one has
// to come here and say it is safe to show an unprivileged user. The agent id,
// account id and key fingerprint are deliberately absent — they belong to the
// administrator's `dtp-agent status`.
func TestPublicStatusCarriesOnlyWhatAnyUserMaySee(t *testing.T) {
	raw, err := json.Marshal(&PublicStatus{ServerURL: "x", LastRunAt: "x", LastError: "x"})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	var got []string
	for k := range fields {
		got = append(got, k)
	}
	sort.Strings(got)

	want := []string{"last_error", "last_run_at", "observed", "phase", "recorded", "rejected", "server_url", "updated_at", "version"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("public status fields are %v, want exactly %v", got, want)
	}
}
