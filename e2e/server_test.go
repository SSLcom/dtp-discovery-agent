package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// fakeDTP is the server half of the protocol, only as far as the agent can
// tell. It exists because the agent repository CANNOT boot a real DTP: the
// engines are private, the image is private, and the whole design of this repo
// is that it depends on none of them. What it CAN do is speak the documented
// protocol and record what arrived — which is where the two bugs that reached
// v0.2.0 and v0.2.1 actually lived.
//
// Faithfulness that matters, because the agent branches on each:
//
//   - /token answers 202 while the registration is pending. That is a 2xx, and
//     a client checking only `err != nil` accepts it and proceeds with an empty
//     bearer token.
//   - /token answers 403 once revoked, which must stop the agent reporting.
//   - Every request body is kept verbatim, so the no-key-material assertion is
//     about what crossed the wire rather than about what the agent intended.
type fakeDTP struct {
	mu sync.Mutex

	server *httptest.Server

	approved bool
	revoked  bool

	registered   []map[string]any
	inventories  []inventoryPage
	bodies       []string // every request body, verbatim
	tokenGrants  int
	tokenPending int
	tokenRefused int
}

type inventoryPage struct {
	RunID            string           `json:"run_id"`
	Final            bool             `json:"final"`
	CompletedSources []string         `json:"completed_sources"`
	CollectorErrors  []map[string]any `json:"collector_errors"`
	Observations     []observation    `json:"observations"`
}

type observation struct {
	CertificatePEM     string            `json:"certificate_pem"`
	ChainPEM           string            `json:"chain_pem"`
	Source             string            `json:"source"`
	Location           string            `json:"location"`
	Binding            map[string]string `json:"binding"`
	PrivateKeyPresent  bool              `json:"private_key_present"`
	PrivateKeyLocation string            `json:"private_key_location"`
	FileMode           string            `json:"file_mode"`
}

func newFakeDTP() *fakeDTP {
	f := &fakeDTP{}
	mux := http.NewServeMux()
	mux.HandleFunc("/discovery/v1/register", f.register)
	mux.HandleFunc("/discovery/v1/token", f.token)
	mux.HandleFunc("/discovery/v1/checkin", f.checkin)
	mux.HandleFunc("/discovery/v1/inventory", f.inventory)
	f.server = httptest.NewServer(mux)
	return f
}

func (f *fakeDTP) close()      { f.server.Close() }
func (f *fakeDTP) url() string { return f.server.URL }

func (f *fakeDTP) approve() { f.mu.Lock(); f.approved = true; f.mu.Unlock() }
func (f *fakeDTP) revoke()  { f.mu.Lock(); f.revoked = true; f.mu.Unlock() }

// record keeps the body before anything else looks at it.
func (f *fakeDTP) record(r *http.Request) []byte {
	buf := make([]byte, 0)
	if r.Body != nil {
		b := make([]byte, 1<<20)
		n, _ := r.Body.Read(b)
		for n > 0 {
			buf = append(buf, b[:n]...)
			n, _ = r.Body.Read(b)
		}
	}
	f.mu.Lock()
	f.bodies = append(f.bodies, string(buf))
	f.mu.Unlock()
	return buf
}

func (f *fakeDTP) register(w http.ResponseWriter, r *http.Request) {
	body := f.record(r)
	var req map[string]any
	_ = json.Unmarshal(body, &req)

	f.mu.Lock()
	f.registered = append(f.registered, req)
	f.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"agent_id":        "agent-e2e",
		"registration_id": "reg-e2e",
		"status":          "pending",
		"key_fingerprint": "fp-e2e",
	})
}

func (f *fakeDTP) token(w http.ResponseWriter, r *http.Request) {
	f.record(r)

	f.mu.Lock()
	revoked, approved := f.revoked, f.approved
	switch {
	case revoked:
		f.tokenRefused++
	case approved:
		f.tokenGrants++
	default:
		f.tokenPending++
	}
	f.mu.Unlock()

	switch {
	case revoked:
		writeJSON(w, http.StatusForbidden, map[string]any{"agent_status": "revoked"})
	case !approved:
		// 202, not 401. An installer run before anyone clicked approve must
		// wait rather than fail.
		writeJSON(w, http.StatusAccepted, map[string]any{"status": "pending", "retry_after": 1})
	default:
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "bearer-e2e", "expires_in": 900})
	}
}

func (f *fakeDTP) checkin(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "agent_id": "agent-e2e"})
}

func (f *fakeDTP) inventory(w http.ResponseWriter, r *http.Request) {
	body := f.record(r)
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]any{})
		return
	}
	var page inventoryPage
	_ = json.Unmarshal(body, &page)

	f.mu.Lock()
	f.inventories = append(f.inventories, page)
	f.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"run_id": page.RunID, "status": "completed",
		"recorded": len(page.Observations), "rejected": 0,
	})
}

// observations flattens every page of every run reported so far.
func (f *fakeDTP) observations() []observation {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []observation
	for _, page := range f.inventories {
		out = append(out, page.Observations...)
	}
	return out
}

func (f *fakeDTP) allBodies() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.bodies, "\n")
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
