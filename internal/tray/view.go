// Package tray decides what the Windows notification-area icon shows.
//
// IT IS PORTABLE ON PURPOSE, for the same reason internal/service is: the
// judgement — which state is good news, which needs a person, what the words
// say — is the part worth testing, and none of it is Windows. The Win32 glue in
// cmd/dtp-agent-tray only draws what this returns.
//
// THE ICON IS ADVISORY. It reads what the service publishes and what the
// Service Control Manager says, and has no way to ask DTP anything — it runs as
// whoever is signed in and holds none of the agent's credentials. So it never
// claims more than those two sources can support: "last reported at 10:42" is
// a fact the service wrote down; "DTP has your certificates" would not be.
package tray

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/SSLcom/dtp-discovery-agent/internal/state"
)

// Service is the agent service's state as the Service Control Manager reports
// it, reduced to what changes the icon.
type Service int

const (
	ServiceUnknown Service = iota
	ServiceNotInstalled
	ServiceStopped
	ServiceStarting
	ServiceRunning
	ServiceStopping
)

// Health is the icon's colour, and the order matters: worse is larger.
type Health int

const (
	Good Health = iota
	Attention
	Problem
	Unknown
)

// StaleAfter is how long a reporting agent may go without a report before the
// icon says so. The service reports hourly with up to fifteen minutes of
// jitter, and a scan takes time of its own, so three hours is two missed
// cycles — long enough never to fire on a healthy host, short enough that a
// person looking at the icon learns about it the same day.
const StaleAfter = 3 * time.Hour

// heartbeat is how long each phase may go unwritten before the icon calls it
// stuck: generous multiples of how often the service rewrites it. Pending is
// rewritten on every retry, at whatever interval the server asks for.
var heartbeat = map[string]time.Duration{
	state.PhaseNotEnrolled: 10 * time.Minute,
	state.PhasePending:     30 * time.Minute,
	state.PhaseScheduled:   StaleAfter,
	state.PhaseScanning:    StaleAfter,
}

// View is everything the icon shows.
type View struct {
	Health   Health
	Headline string   // the first line of the menu, and the tooltip
	Details  []string // further lines in the menu, greyed out

	// ServerURL is the DTP the agent reports to, when it is known and is a
	// web address. "Open DTP" is offered only when this is set.
	ServerURL string

	// NeedsEnrollment offers "How to enroll…" in the menu.
	NeedsEnrollment bool
}

// Tooltip is the hover text. Windows truncates a notification-area tooltip at
// 127 characters, mid-word, so it is cut here instead, on a boundary.
func (v View) Tooltip() string {
	tip := "DTP Agent: " + v.Headline
	const limit = 127
	if r := []rune(tip); len(r) > limit {
		tip = strings.TrimSpace(string(r[:limit-1])) + "…"
	}
	return tip
}

// Describe turns the two sources into a View. readErr is the error from reading
// the published status, if any; st is nil when there is none to read.
func Describe(svc Service, st *state.PublicStatus, readErr error, now time.Time) View {
	switch svc {
	case ServiceNotInstalled:
		return View{
			Health:   Problem,
			Headline: "The agent service is not installed",
			Details:  []string{"Reinstall the agent from its .msi to register the service."},
		}
	case ServiceStopped:
		return View{
			Health:   Problem,
			Headline: "The agent service is stopped",
			Details:  []string{"Nothing is being reported. Start it from an administrator prompt:", "sc.exe start DTPAgent"},
		}
	case ServiceStopping:
		return View{Health: Attention, Headline: "The agent service is stopping"}
	}

	if readErr != nil {
		return View{
			Health:   Unknown,
			Headline: "Cannot read the agent's status",
			Details:  []string{readErr.Error()},
		}
	}
	if st == nil {
		// A service from before the icon existed, or one that has not written
		// yet. The service manager is the only source left, and it is enough
		// to say the thing is alive.
		if svc == ServiceRunning || svc == ServiceStarting {
			return View{Health: Unknown, Headline: "Running; no status published yet"}
		}
		return View{Health: Unknown, Headline: "Agent status unknown"}
	}

	v := View{ServerURL: webURL(st.ServerURL)}
	host := hostOf(st.ServerURL)
	last := lastReport(st, now)

	switch st.Phase {
	case state.PhaseNotEnrolled:
		v.Health = Attention
		v.Headline = "Installed, but not enrolled yet"
		v.Details = []string{"This machine reports nothing until it is enrolled with a DTP account."}
		v.NeedsEnrollment = true

	case state.PhasePending:
		v.Health = Attention
		v.Headline = "Waiting for approval"
		v.Details = []string{"An account admin needs to admit this agent in DTP" + inHost(host) + "."}

	case state.PhaseScheduled:
		v.Health = Good
		v.Headline = "Enrolled; first scan is a few minutes away"

	case state.PhaseScanning:
		v.Health = Good
		v.Headline = "Scanning this machine"
		if last != "" {
			v.Details = []string{last}
		}

	case state.PhaseReporting:
		v.Health = Good
		v.Headline = "Reporting" + toHost(host)
		if last != "" {
			v.Details = []string{last}
		}
		if t, ok := parseTime(st.LastRunAt); ok && now.Sub(t) > StaleAfter {
			v.Health = Attention
			v.Headline = "No report since " + when(t, now)
			v.Details = []string{"The service is running but has not completed a scan recently."}
		}
		if st.Rejected > 0 {
			v.Details = append(v.Details, fmt.Sprintf("DTP rejected %d of the last report's observations.", st.Rejected))
		}

	case state.PhaseFailed:
		v.Health = Problem
		v.Headline = "The last report failed"
		if st.LastError != "" {
			v.Details = append(v.Details, clip(st.LastError, 160))
		}
		if last != "" {
			v.Details = append(v.Details, last)
		}

	default:
		// A newer service than this icon. Say what it said rather than guess.
		v.Health = Unknown
		v.Headline = "Agent status: " + st.Phase
	}

	// A STATUS THAT HAS STOPPED MOVING. Every phase but "reporting" (judged by
	// its last report, above) is rewritten while it lasts — the enrollment
	// poll every minute, a pending approval on every retry — so one that has
	// not been touched in far longer than that is a service that is running
	// but wedged, and "Scanning this machine" in green forever would hide it.
	if limit, ok := heartbeat[st.Phase]; ok && svc == ServiceRunning {
		if t, ok := parseTime(st.UpdatedAt); ok && now.Sub(t) > limit {
			if v.Health < Attention {
				v.Health = Attention
			}
			v.Details = append(v.Details, "Status not updated since "+when(t, now)+".")
		}
	}

	if svc != ServiceRunning && svc != ServiceStarting && v.Health < Attention {
		// The file says all is well, but the service manager does not vouch for
		// the process that wrote it. Believe the one that is live.
		v.Health = Attention
	}
	return v
}

func lastReport(st *state.PublicStatus, now time.Time) string {
	t, ok := parseTime(st.LastRunAt)
	if !ok {
		return ""
	}
	return fmt.Sprintf("Last report %s: %d certificate%s found", when(t, now), st.Observed, plural(st.Observed))
}

// when is a time as a person at this machine reads it: their own clock, and
// the date only when it is not today.
func when(t, now time.Time) string {
	t = t.In(now.Location())
	y1, m1, d1 := t.Date()
	y2, m2, d2 := now.Date()
	if y1 == y2 && m1 == m2 && d1 == d2 {
		return t.Format("15:04")
	}
	return t.Format("2 Jan 15:04")
}

func parseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

// webURL returns the address only if it is one a browser should be handed. The
// icon opens it with the shell, and the shell will run anything it is given.
func webURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	return u.String()
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func toHost(host string) string {
	if host == "" {
		return ""
	}
	return " to " + host
}

func inHost(host string) string {
	if host == "" {
		return ""
	}
	return " (" + host + ")"
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
