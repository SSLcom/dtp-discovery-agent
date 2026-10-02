//go:build windows

package main

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/svc"

	"github.com/SSLcom/dtp-discovery-agent/internal/service"
)

// serviceState answers, in one line, the first question anybody asks about this
// agent on Windows: is the thing running.
//
// It is reported by `dtp-agent status` rather than left to services.msc because
// the two facts a member needs — the service is running, and here is what it
// last found — are otherwise in two different places, and the one that is
// easiest to check is the one that does not say whether anything was reported.
//
// Every failure is REPORTED, not swallowed. "Not installed" is a real and
// common answer (a member who unzipped the archive instead of running the
// installer), and it is the answer that explains why nothing is happening.
func serviceState() string {
	state, err := service.Query()
	if errors.Is(err, service.ErrNotInstalled) {
		return "not installed — install the .msi, or the agent will only run when you run it"
	}
	if err != nil {
		return fmt.Sprintf("unknown (%v)", err)
	}

	switch state {
	case svc.Running:
		return "running"
	case svc.Stopped:
		return "stopped — sc.exe start " + service.Name
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Paused, svc.PausePending, svc.ContinuePending:
		return "paused"
	default:
		return fmt.Sprintf("state %d", state)
	}
}
