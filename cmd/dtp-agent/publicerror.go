package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/SSLcom/dtp-discovery-agent/internal/state"
	"github.com/SSLcom/dtp-discovery-agent/internal/transport"
)

// publicError says what went wrong in words fit for EVERY USER OF THE MACHINE,
// because that is who can read the status the service publishes for the
// notification-area icon.
//
// NEVER err.Error(). For a refused request that string carries the response
// body verbatim — up to a megabyte of whatever the server, or a proxy or
// captive portal in the way, chose to say — and a summary any local account
// can read is no place for text nobody here wrote. The full error still goes
// to the service log and last-run.json, both inside the closed state
// directory, where `dtp-agent status` shows it to an administrator.
//
// So this names a CATEGORY, built only from values the agent itself chose.
func publicError(err error) string {
	var refused *transport.ErrRefused
	var urlErr *url.Error
	var netErr net.Error
	switch {
	case err == nil:
		return ""
	case errors.Is(err, state.ErrNotEnrolled):
		return "This agent is not enrolled."
	case errors.As(err, &refused):
		return "DTP refused this agent: it is " + safeWord(refused.AgentStatus) + "."
	case errors.Is(err, transport.ErrKeyMaterialOutbound):
		return "The agent refused to send a report that looked like it held key material."
	case errors.Is(err, context.DeadlineExceeded):
		return "The DTP server did not answer in time."
	}
	if code, ok := transport.HTTPStatus(err); ok {
		return fmt.Sprintf("The DTP server answered HTTP %d.", code)
	}
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "The DTP server did not answer in time."
	}
	if errors.As(err, &urlErr) {
		return "Could not reach the DTP server."
	}
	return "The last report failed."
}

// safeWord passes an agent status through only if it is a short plain word,
// which every status the protocol defines is. Anything else is the server
// saying something unexpected, and this is not the place to repeat it.
func safeWord(s string) string {
	if len(s) == 0 || len(s) > 20 {
		return "not allowed to report"
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && r != '_' {
			return "not allowed to report"
		}
	}
	return s
}
