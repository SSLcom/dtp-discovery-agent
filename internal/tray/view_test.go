package tray

import (
	"bytes"
	"errors"
	"image/png"
	"strings"
	"testing"
	"time"

	"github.com/SSLcom/dtp-discovery-agent/internal/state"
)

var now = time.Date(2026, 10, 1, 14, 0, 0, 0, time.UTC)

func status(phase string) *state.PublicStatus {
	return &state.PublicStatus{
		Phase: phase, ServerURL: "https://dtp.example.com",
		LastRunAt: "2026-10-01T13:10:00Z", Observed: 12, Recorded: 12,
	}
}

func TestEachPhaseHasTheHealthItMeans(t *testing.T) {
	for _, tc := range []struct {
		phase string
		want  Health
	}{
		{state.PhaseNotEnrolled, Attention},
		{state.PhasePending, Attention},
		{state.PhaseScheduled, Good},
		{state.PhaseScanning, Good},
		{state.PhaseReporting, Good},
		{state.PhaseFailed, Problem},
		{"something_newer", Unknown},
	} {
		if got := Describe(ServiceRunning, status(tc.phase), nil, now).Health; got != tc.want {
			t.Errorf("%s: health %d, want %d", tc.phase, got, tc.want)
		}
	}
}

// The service manager is live and the file is a record. When they disagree,
// the icon believes the one that is live: a stopped service with a cheerful
// status file is a host that is not reporting.
func TestAStoppedServiceOutranksAGoodStatusFile(t *testing.T) {
	v := Describe(ServiceStopped, status(state.PhaseReporting), nil, now)
	if v.Health != Problem || !strings.Contains(v.Headline, "stopped") {
		t.Errorf("got %+v", v)
	}
	if v := Describe(ServiceNotInstalled, status(state.PhaseReporting), nil, now); v.Health != Problem {
		t.Errorf("not installed: got %+v", v)
	}
	if v := Describe(ServiceUnknown, status(state.PhaseReporting), nil, now); v.Health == Good {
		t.Error("a status the service manager does not vouch for was shown as good")
	}
}

func TestReportingSaysWhereAndWhen(t *testing.T) {
	v := Describe(ServiceRunning, status(state.PhaseReporting), nil, now)
	if v.Headline != "Reporting to dtp.example.com" {
		t.Errorf("headline %q", v.Headline)
	}
	if len(v.Details) == 0 || v.Details[0] != "Last report 13:10: 12 certificates found" {
		t.Errorf("details %q", v.Details)
	}
	if v.ServerURL != "https://dtp.example.com" {
		t.Errorf("server URL %q", v.ServerURL)
	}
}

// Hourly reporting with jitter: two missed cycles is a host worth a look, and
// "Reporting" over a report from yesterday would be a lie the icon told.
func TestAReportThatIsHoursOldIsCalledOut(t *testing.T) {
	st := status(state.PhaseReporting)
	st.LastRunAt = now.Add(-StaleAfter - time.Minute).Format(time.RFC3339)
	v := Describe(ServiceRunning, st, nil, now)
	if v.Health != Attention || !strings.HasPrefix(v.Headline, "No report since") {
		t.Errorf("got %+v", v)
	}
}

func TestAFailureShowsWhy(t *testing.T) {
	st := status(state.PhaseFailed)
	st.LastError = "registering with https://dtp.example.com: connection refused"
	v := Describe(ServiceRunning, st, nil, now)
	if v.Health != Problem || len(v.Details) == 0 || !strings.Contains(v.Details[0], "connection refused") {
		t.Errorf("got %+v", v)
	}
}

func TestOnlyAnUnenrolledAgentOffersEnrollment(t *testing.T) {
	if !Describe(ServiceRunning, status(state.PhaseNotEnrolled), nil, now).NeedsEnrollment {
		t.Error("an unenrolled agent does not offer the way to enroll it")
	}
	if Describe(ServiceRunning, status(state.PhaseReporting), nil, now).NeedsEnrollment {
		t.Error("a reporting agent offers enrollment")
	}
}

// The icon hands this address to the shell, and the shell runs whatever it is
// given. The file is written by SYSTEM into a directory users cannot write, so
// this is belt and braces — but the braces cost one line.
func TestOnlyAWebAddressIsOfferedToOpen(t *testing.T) {
	for raw, want := range map[string]string{
		"https://dtp.example.com":        "https://dtp.example.com",
		"http://127.0.0.1:3000":          "http://127.0.0.1:3000",
		`C:\Windows\System32\calc.exe`:   "",
		"file:///C:/Windows/notepad.exe": "",
		"javascript:alert(1)":            "",
		"":                               "",
	} {
		st := status(state.PhaseReporting)
		st.ServerURL = raw
		if got := Describe(ServiceRunning, st, nil, now).ServerURL; got != want {
			t.Errorf("%q: offered %q, want %q", raw, got, want)
		}
	}
}

func TestNoStatusFileIsNotAFailure(t *testing.T) {
	v := Describe(ServiceRunning, nil, nil, now)
	if v.Health != Unknown || !strings.Contains(v.Headline, "Running") {
		t.Errorf("got %+v", v)
	}
	v = Describe(ServiceRunning, nil, errors.New("access is denied"), now)
	if v.Health != Unknown || len(v.Details) == 0 || v.Details[0] != "access is denied" {
		t.Errorf("unreadable: got %+v", v)
	}
}

func TestTheTooltipFitsWhatWindowsShows(t *testing.T) {
	st := status(state.PhaseReporting)
	st.ServerURL = "https://" + strings.Repeat("very-long-subdomain.", 10) + "example.com"
	tip := Describe(ServiceRunning, st, nil, now).Tooltip()
	if n := len([]rune(tip)); n > 127 {
		t.Errorf("tooltip is %d characters; Windows cuts it at 127", n)
	}
}

func TestEveryIconIsAValidImageOfTheAskedSize(t *testing.T) {
	for _, h := range []Health{Good, Attention, Problem, Unknown} {
		for _, size := range []int{16, 20, 24, 32, 48} {
			img, err := png.Decode(bytes.NewReader(Icon(h, size)))
			if err != nil {
				t.Fatalf("health %d, %dpx: %v", h, size, err)
			}
			if b := img.Bounds(); b.Dx() != size || b.Dy() != size {
				t.Errorf("health %d: %v, want %dx%d", h, b, size, size)
			}
			// The corners are outside the disc. An opaque corner means the icon
			// would sit on the taskbar as a coloured square.
			if _, _, _, a := img.At(0, 0).RGBA(); a != 0 {
				t.Errorf("health %d, %dpx: the corner is not transparent", h, size)
			}
		}
	}
}

// Shape, not only colour: no two states may draw the same glyph.
func TestEveryHealthLooksDifferent(t *testing.T) {
	seen := map[string]Health{}
	for _, h := range []Health{Good, Attention, Problem, Unknown} {
		img, _ := png.Decode(bytes.NewReader(Icon(h, 16)))
		var mask strings.Builder
		for y := 0; y < 16; y++ {
			for x := 0; x < 16; x++ {
				r, g, b, a := img.At(x, y).RGBA()
				// White-ish and opaque: the glyph.
				if a > 0x8000 && r > 0xc000 && g > 0xc000 && b > 0xc000 {
					mask.WriteByte('#')
				} else {
					mask.WriteByte('.')
				}
			}
		}
		if other, dup := seen[mask.String()]; dup {
			t.Errorf("health %d draws the same glyph as health %d", h, other)
		}
		seen[mask.String()] = h
	}
}
