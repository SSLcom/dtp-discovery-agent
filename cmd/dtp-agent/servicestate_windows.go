//go:build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

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
	m, err := mgr.Connect()
	if err != nil {
		// Connecting asks for full access to the service database, which needs
		// an elevated prompt. Worth saying: the rest of this command works
		// unelevated only until it reaches the state directory, so a member
		// seeing this is one step from being confused by the next error too.
		return fmt.Sprintf("unknown (%v) — try an administrator prompt", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(service.Name)
	if err != nil {
		if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return "not installed — install the .msi, or the agent will only run when you run it"
		}
		return fmt.Sprintf("unknown (%v)", err)
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return fmt.Sprintf("unknown (%v)", err)
	}

	switch status.State {
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
		return fmt.Sprintf("state %d", status.State)
	}
}
