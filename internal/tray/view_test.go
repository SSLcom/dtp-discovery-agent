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
			for _, dark := range []bool{true, false} {
				img, err := png.Decode(bytes.NewReader(Icon(h, size, dark)))
				if err != nil {
					t.Fatalf("health %d, %dpx: %v", h, size, err)
				}
				if b := img.Bounds(); b.Dx() != size || b.Dy() != size {
					t.Errorf("health %d: %v, want %dx%d", h, b, size, size)
				}
				// Outside the mark and the badge. An opaque corner means the
				// icon would sit on the taskbar as a coloured square.
				for _, c := range [][2]int{{0, 0}, {size - 1, size - 1}} {
					if _, _, _, a := img.At(c[0], c[1]).RGBA(); a != 0 {
						t.Errorf("health %d, %dpx: corner %v is not transparent", h, size, c)
					}
				}
			}
		}
	}
}

// Every state looks different from every other — including from the plain
// mark, which is what "all is well" looks like.
func TestEveryHealthLooksDifferent(t *testing.T) {
	seen := map[string]Health{}
	for _, h := range []Health{Good, Attention, Problem, Unknown} {
		key := string(Icon(h, 16, true))
		if other, dup := seen[key]; dup {
			t.Errorf("health %d draws the same icon as health %d", h, other)
		}
		seen[key] = h
	}
}

// A healthy machine shows the plain mark: one ink, nothing else.
func TestAllIsWellIsThePlainMark(t *testing.T) {
	for _, dark := range []bool{true, false} {
		img, _ := png.Decode(bytes.NewReader(Icon(Good, 32, dark)))
		want := [3]uint32{0x19, 0x15, 0x21}
		if dark {
			want = [3]uint32{0xff, 0xff, 0xff}
		}
		inked := 0
		for y := 0; y < 32; y++ {
			for x := 0; x < 32; x++ {
				r, g, b, a := img.At(x, y).RGBA()
				if a < 0xffff {
					continue // an edge pixel, partly transparent
				}
				inked++
				if r>>8 != want[0] || g>>8 != want[1] || b>>8 != want[2] {
					t.Fatalf("dark=%v: pixel (%d,%d) is %02x%02x%02x, not the mark's ink", dark, x, y, r>>8, g>>8, b>>8)
				}
			}
		}
		if inked < 100 {
			t.Errorf("dark=%v: only %d pixels of mark at 32 px", dark, inked)
		}
	}
}

// The brand ink would vanish on a dark taskbar — the Windows 11 default.
func TestTheMarkFollowsTheTaskbar(t *testing.T) {
	if bytes.Equal(Icon(Good, 16, true), Icon(Good, 16, false)) {
		t.Error("the icon is the same on a dark taskbar and a light one")
	}
}

// THE MARK IS DRAWN RIGHT. The pinwheel turns onto itself every quarter turn,
// so a misread path command, a wrongly flattened curve or a broken fill rule
// shows up as asymmetry — and its centre is an open square.
func TestThePinwheelIsDrawnAsThePinwheel(t *testing.T) {
	m := pinwheel()
	if m.contains(0.5, 0.5) {
		t.Error("the centre of the pinwheel is filled; the mark has an open square there")
	}
	const n = 200
	inside, mismatch := 0, 0
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			x, y := (float64(i)+0.5)/n, (float64(j)+0.5)/n
			a := m.contains(x, y)
			// A quarter turn about the centre.
			if a != m.contains(1-y, x) {
				mismatch++
			}
			if a {
				inside++
			}
		}
	}
	if frac := float64(inside) / (n * n); frac < 0.25 || frac > 0.6 {
		t.Errorf("the mark covers %.0f%% of its square, which is not the pinwheel", frac*100)
	}
	// The published paths are hand-drawn to within a fraction of a unit, so
	// allow the edges a little.
	if frac := float64(mismatch) / float64(inside); frac > 0.04 {
		t.Errorf("%.1f%% of the mark changes under a quarter turn; the pinwheel is symmetric", frac*100)
	}
}

func TestTheMarkUsesOnlyWhatTheParserReads(t *testing.T) {
	for _, d := range pinwheelPaths {
		for _, c := range d {
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				if !strings.ContainsRune("MLHVCZ", c) {
					t.Errorf("the mark uses path command %q, which parsePath does not read", c)
				}
			}
		}
	}
}

func TestAWedgedScanIsNotShownAsHealthy(t *testing.T) {
	st := status(state.PhaseScanning)
	st.UpdatedAt = now.Add(-StaleAfter - time.Minute).Format(time.RFC3339)
	v := Describe(ServiceRunning, st, nil, now)
	if v.Health != Attention || !strings.Contains(strings.Join(v.Details, " "), "not updated since") {
		t.Errorf("a scan that has said nothing for hours is shown as %+v", v)
	}

	st.UpdatedAt = now.Add(-time.Minute).Format(time.RFC3339)
	if v := Describe(ServiceRunning, st, nil, now); v.Health != Good {
		t.Errorf("a scan that started a minute ago is shown as %+v", v)
	}
}

func TestAnEnrollmentPollThatStoppedIsCalledOut(t *testing.T) {
	st := status(state.PhaseNotEnrolled)
	st.UpdatedAt = now.Add(-15 * time.Minute).Format(time.RFC3339)
	if v := Describe(ServiceRunning, st, nil, now); !strings.Contains(strings.Join(v.Details, " "), "not updated since") {
		t.Errorf("the minute-by-minute poll has been silent for 15 minutes and nothing says so: %+v", v)
	}
}
