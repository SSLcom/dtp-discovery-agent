// Package transport speaks the DTP agent protocol.
//
// Three properties this package is responsible for, each of which fails
// silently if it is dropped:
//
//  1. Every /token request carries X-DTP-Agent-Fingerprint. Nothing on the
//     server reads it — the host's rate limiter does, because middleware cannot
//     parse a JSON body. An agent that omits it still authenticates, and joins
//     the shared per-IP bucket with every other agent behind the same address.
//     For a fleet inside one customer's network that is all of them.
//
//  2. The final inventory page carries completed_sources. It is the only thing
//     that lets DTP conclude a certificate is no longer deployed. Omitting it
//     marks nothing absent — stale but safe — so the bug would show up as an
//     inventory that never shrinks rather than as an error.
//
//  3. No private key material leaves this process. See guard.go.
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/SSLcom/dtp-discovery-agent/internal/collect"
)

const (
	// The server caps a page at 500 observations and answers 413 above it.
	// Matched here so the agent pages itself rather than learning the limit
	// from a rejection.
	MaxObservationsPerPage = 500

	defaultTimeout = 30 * time.Second
	userAgent      = "dtp-agent"
)

type Client struct {
	BaseURL string
	Version string
	HTTP    *http.Client

	token          string
	tokenExpiresAt time.Time
}

func New(baseURL, version string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Version: version,
		HTTP:    &http.Client{Timeout: defaultTimeout},
	}
}

// ── errors worth distinguishing ──────────────────────────────────────────────

// ErrPendingApproval is the 202 from /token: the agent proved it holds its key
// and a human has not yet admitted it. NOT an authentication failure, and the
// installer must not present it as one — running the installer before anyone
// clicks approve is the normal case, not a mistake.
type ErrPendingApproval struct{ RetryAfter time.Duration }

func (e *ErrPendingApproval) Error() string {
	return fmt.Sprintf("waiting for an account admin to approve this agent (retry in %s)", e.RetryAfter)
}

// ErrRefused is the 403: a valid key, refused standing — suspended, revoked, or
// its account archived. Terminal, so the agent says so rather than retrying
// forever.
type ErrRefused struct{ AgentStatus string }

func (e *ErrRefused) Error() string {
	return fmt.Sprintf("this agent is %s and may not report", e.AgentStatus)
}

// ── register ─────────────────────────────────────────────────────────────────

type RegisterRequest struct {
	PublicKeyPEM    string            `json:"public_key_pem"`
	AccountID       string            `json:"account_id"`
	EnrollmentToken string            `json:"enrollment_token,omitempty"`
	HostFacts       map[string]string `json:"host_facts"`
}

type RegisterResponse struct {
	AgentID        string `json:"agent_id"`
	RegistrationID string `json:"registration_id"`
	Status         string `json:"status"`
	KeyFingerprint string `json:"key_fingerprint"`
}

func (c *Client) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	out := &RegisterResponse{}
	if _, err := c.do(ctx, "POST", "/discovery/v1/register", nil, req, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ── token ────────────────────────────────────────────────────────────────────

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Status      string `json:"status"`
	AgentStatus string `json:"agent_status"`
	RetryAfter  int    `json:"retry_after"`
}

// Authenticate exchanges a signed assertion for a bearer token, caching it
// until shortly before it expires.
func (c *Client) Authenticate(ctx context.Context, signer *Signer) error {
	// A minute of headroom: a token that expires mid-upload costs a retry of a
	// whole page, and the exchange is cheap.
	if c.token != "" && time.Now().Before(c.tokenExpiresAt.Add(-time.Minute)) {
		return nil
	}

	assertion, err := signer.Assertion()
	if err != nil {
		return err
	}

	// THE HEADER. See the package comment — its absence is invisible from here
	// and costs the whole fleet its per-agent rate limit.
	headers := map[string]string{"X-DTP-Agent-Fingerprint": signer.Fingerprint}

	out := &tokenResponse{}
	code, err := c.do(ctx, "POST", "/discovery/v1/token", headers, assertion, out)

	// 202 FIRST, before the error check: it is a 2xx, so `err` is nil here and
	// a plain success path would accept an empty token.
	if code == http.StatusAccepted {
		retry := time.Duration(out.RetryAfter) * time.Second
		if retry <= 0 {
			retry = 30 * time.Second
		}
		return &ErrPendingApproval{RetryAfter: retry}
	}
	if code == http.StatusForbidden {
		return &ErrRefused{AgentStatus: out.AgentStatus}
	}
	if err != nil {
		return err
	}
	if out.AccessToken == "" {
		// A 2xx that carried no token. Should not happen; if the protocol ever
		// grows another accepted-but-not-granted state, this refuses rather
		// than proceeding with an empty Authorization header.
		return errors.New("server accepted the assertion but returned no access token")
	}

	c.token = out.AccessToken
	c.tokenExpiresAt = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return nil
}

// ── checkin ──────────────────────────────────────────────────────────────────

type CheckinResponse struct {
	OK         bool     `json:"ok"`
	AgentID    string   `json:"agent_id"`
	ServerTime string   `json:"server_time"`
	Commands   []string `json:"commands"`
}

func (c *Client) Checkin(ctx context.Context) (*CheckinResponse, error) {
	out := &CheckinResponse{}
	body := map[string]string{"agent_version": c.Version}
	if _, err := c.do(ctx, "POST", "/discovery/v1/checkin", c.bearer(), body, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ClockSkew reports how far this host's clock is from the server's. Drift is the
// commonest cause of a fleet that suddenly cannot authenticate — assertions are
// signed with the local clock and rejected outside a two-minute window — so the
// agent surfaces it in its own logs rather than leaving an operator to guess.
func (r *CheckinResponse) ClockSkew() (time.Duration, bool) {
	serverTime, err := time.Parse(time.RFC3339, r.ServerTime)
	if err != nil {
		return 0, false
	}
	return time.Since(serverTime), true
}

// ── inventory ────────────────────────────────────────────────────────────────

type InventoryPage struct {
	RunID            string                `json:"run_id"`
	StartedAt        string                `json:"started_at,omitempty"`
	FinishedAt       string                `json:"finished_at,omitempty"`
	Final            bool                  `json:"final"`
	CompletedSources []string              `json:"completed_sources,omitempty"`
	CollectorErrors  []collect.Error       `json:"collector_errors,omitempty"`
	Observations     []collect.Observation `json:"observations"`
}

type InventoryResponse struct {
	RunID    string   `json:"run_id"`
	Status   string   `json:"status"`
	Recorded int      `json:"recorded"`
	Rejected int      `json:"rejected"`
	Errors   []string `json:"errors"`
}

func (c *Client) Inventory(ctx context.Context, page InventoryPage) (*InventoryResponse, error) {
	out := &InventoryResponse{}
	if _, err := c.do(ctx, "POST", "/discovery/v1/inventory", c.bearer(), page, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) bearer() map[string]string {
	return map[string]string{"Authorization": "Bearer " + c.token}
}

// ── plumbing ─────────────────────────────────────────────────────────────────

type statusError struct {
	Code int
	Body string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("server returned %d: %s", e.Code, strings.TrimSpace(e.Body))
}

// do performs one request and RETURNS THE STATUS CODE alongside the error.
//
// The code matters because 202 is a success as far as HTTP is concerned and a
// "not yet" as far as this protocol is concerned: /token answers 202 while a
// human has not approved the agent. Collapsing that into `err == nil` would
// hand the caller an empty access token and a cheerful exit — the installer
// would look like it worked and every later call would fail for no stated
// reason.
func (c *Client) do(ctx context.Context, method, path string, headers map[string]string, in, out any) (int, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return 0, err
	}

	// THE OUTBOUND GUARD. Every request body passes through it, so a collector
	// or a future field that carries key material is stopped here rather than
	// at the server — which would refuse it, but only after it had crossed the
	// network. See guard.go.
	if err := guardOutbound(body); err != nil {
		return 0, err
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent+"/"+c.Version)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// Bounded: a proxy or a captive portal can answer with something enormous,
	// and the agent must not read it into memory on a customer's machine.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if out != nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, out)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, &statusError{Code: resp.StatusCode, Body: string(raw)}
	}
	return resp.StatusCode, nil
}
