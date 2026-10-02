package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SSLcom/dtp-discovery-agent/internal/transport"
)

// The test this function exists for: a server, or a proxy in front of it,
// answers an error with a body, and that body must not reach the summary every
// user of the machine can read. Driven through the real client, so the error
// shape is the one the service actually sees.
func TestAnErrorBodyNeverReachesThePublicStatus(t *testing.T) {
	const secret = "proxy-session=hunter2"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, "<html>upstream failed; "+secret+"</html>")
	}))
	defer srv.Close()

	_, err := transport.New(srv.URL, "test").Register(context.Background(), transport.RegisterRequest{})
	if err == nil || !strings.Contains(err.Error(), secret) {
		t.Fatalf("the setup must produce an error carrying the body, or this proves nothing: %v", err)
	}

	got := publicError(err)
	if strings.Contains(got, secret) || strings.Contains(got, "html") {
		t.Errorf("the public summary repeats the response body: %q", got)
	}
	if !strings.Contains(got, "502") {
		t.Errorf("the public summary lost the one fact that is safe to say, the status code: %q", got)
	}
}

func TestEachKindOfFailureHasItsOwnWords(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&transport.ErrRefused{AgentStatus: "revoked"}, "it is revoked"},
		{&transport.ErrRefused{AgentStatus: "<script>"}, "not allowed to report"},
		{fmt.Errorf("upload: %w", context.DeadlineExceeded), "did not answer in time"},
		{fmt.Errorf("uploading: %w", transport.ErrKeyMaterialOutbound), "key material"},
		{errors.New("something nobody anticipated: with detail"), "The last report failed."},
	} {
		if got := publicError(tc.err); !strings.Contains(got, tc.want) {
			t.Errorf("%v: got %q, want it to contain %q", tc.err, got, tc.want)
		}
	}
	if got := publicError(errors.New("detail that must stay private")); strings.Contains(got, "private") {
		t.Errorf("an unrecognised error was repeated: %q", got)
	}
}
