package main

import (
	"net/url"

	"github.com/SSLcom/dtp-discovery-agent/internal/state"
)

// outcome is what the service publishes once a cycle ends. Portable, and
// separate from the Windows glue, so it is tested everywhere.
//
// resting means "publish what is on disk instead": the cycle was interrupted
// by a stop, and the last real outcome says more to whoever looks than
// "interrupted" would — the service manager already says "stopped".
func outcome(ctxErr, err error) (phase string, cause error, resting bool) {
	switch {
	case ctxErr != nil:
		return "", nil, true
	case err != nil:
		return state.PhaseFailed, err, false
	default:
		return state.PhaseReporting, nil, false
	}
}

// publicServerURL is the DTP address as every user of the machine may see it:
// scheme, host and path. Not credentials someone put in the URL, and not a
// query string, neither of which the icon needs to open the right page.
func publicServerURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}
