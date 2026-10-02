package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/SSLcom/dtp-discovery-agent/internal/collect"
	"github.com/SSLcom/dtp-discovery-agent/internal/state"
)

func TestHowACycleEndsIsWhatIsPublished(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		name        string
		ctxErr, err error
		phase       string
		cause       error
		resting     bool
	}{
		{"success", nil, nil, state.PhaseReporting, nil, false},
		{"failure", nil, boom, state.PhaseFailed, boom, false},
		// A stop is not a failure: an agent stopped mid-scan for a reboot must
		// not show red until it next runs.
		{"stopped mid-cycle", context.Canceled, context.Canceled, "", nil, true},
	} {
		phase, cause, resting := outcome(tc.ctxErr, tc.err)
		if phase != tc.phase || cause != tc.cause || resting != tc.resting {
			t.Errorf("%s: got (%q, %v, %v)", tc.name, phase, cause, resting)
		}
	}
}

func TestOnlyTheAddressIsPublished(t *testing.T) {
	for raw, want := range map[string]string{
		"https://dtp.example.com":                     "https://dtp.example.com",
		"https://user:secret@dtp.example.com/x?t=1#f": "https://dtp.example.com/x",
		"not a url": "",
	} {
		if got := publicServerURL(raw); got != want {
			t.Errorf("%q: got %q, want %q", raw, got, want)
		}
	}
}

// THE PHASE HOOKS, driven through the real cycle against a server that keeps
// the agent waiting once. Removing either call in report.go turns this red —
// and without them the icon says "first scan is a few minutes away" to an
// agent that is in fact waiting for someone to approve it.
func TestACycleAnnouncesEachStageItReaches(t *testing.T) {
	var tokens atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply := func(code int, body map[string]any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(body)
		}
		switch r.URL.Path {
		case "/discovery/v1/token":
			if tokens.Add(1) == 1 {
				reply(http.StatusAccepted, map[string]any{"status": "pending", "retry_after": 1})
				return
			}
			reply(http.StatusOK, map[string]any{"access_token": "t", "expires_in": 900})
		case "/discovery/v1/checkin":
			reply(http.StatusOK, map[string]any{"ok": true})
		case "/discovery/v1/inventory":
			reply(http.StatusOK, map[string]any{"run_id": "r", "status": "completed", "recorded": 0, "rejected": 0})
		default:
			reply(http.StatusNotFound, map[string]any{})
		}
	}))
	defer srv.Close()

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveConfig(&state.Config{ServerURL: srv.URL, AccountID: "a"}); err != nil {
		t.Fatal(err)
	}

	// Only the file collector, over an empty directory: this is about the
	// stages, not about what a scan finds.
	var disabled []string
	for _, name := range collect.Names() {
		if name != "file" {
			disabled = append(disabled, name)
		}
	}
	empty := t.TempDir()

	var (
		mu     sync.Mutex
		phases []string
	)
	out := reporter{
		info:  func(string, ...any) {},
		warn:  func(string, ...any) {},
		phase: func(p string) { mu.Lock(); phases = append(phases, p); mu.Unlock() },
	}
	if err := reportOnce(context.Background(), store.Dir(), []string{empty}, disabled, false, out); err != nil {
		t.Fatal(err)
	}

	want := []string{state.PhasePending, state.PhaseScanning}
	if len(phases) != len(want) || phases[0] != want[0] || phases[1] != want[1] {
		t.Errorf("stages announced %v, want %v", phases, want)
	}
}
