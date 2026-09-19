package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The MSI is the only artefact in this repository that cannot be exercised
// where it is built: wixl produces it on Linux, and only Windows can install
// it. So what CAN be checked from here is checked from here — that the package
// installs the service this binary actually implements.
//
// The failure this prevents is quiet. Rename the service in Go and the MSI goes
// on registering the old name: the installer succeeds, the service appears in
// services.msc, and it starts a binary that does not recognise the name it was
// started under. Nothing errors. The host simply never reports.
func TestPackagingMatchesTheServiceSpec(t *testing.T) {
	path := filepath.Join("..", "..", "packaging", "windows", "dtp-agent.wxs")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	wxs := string(raw)

	for what, literal := range map[string]string{
		"service name":       `Name="` + Name + `"`,
		"display name":       `DisplayName="` + DisplayName + `"`,
		"description":        Description,
		"start argument":     `Arguments="` + Arg + `"`,
		"the binary it runs": `Name="dtp-agent.exe"`,
	} {
		if !strings.Contains(wxs, literal) {
			t.Errorf("dtp-agent.wxs does not carry the %s the code uses (%q)", what, literal)
		}
	}

	// Registered to start itself after a reboot. A discovery agent that has to
	// be started by hand after every patch Tuesday is one that reports for a
	// week and then goes silent, and a silent host looks exactly like a host
	// whose certificates have not changed.
	if !strings.Contains(wxs, `Start="auto"`) {
		t.Error("the service is not registered to start automatically")
	}

	// LocalSystem is deliberate and worth failing on if it is ever quietly
	// narrowed: the certificates worth finding are in stores and directories an
	// unprivileged account cannot read, and an agent that silently sees half
	// the host is worse than one that does not run.
	if !strings.Contains(wxs, `Account="LocalSystem"`) {
		t.Error("the service is not registered to run as LocalSystem")
	}

	// UNINSTALL MUST NOT REACH THE STATE DIRECTORY. It holds the keypair DTP
	// has already approved, so removing it silently turns a reinstall into a
	// re-approval for every host in an estate. The MSI leaves it alone by never
	// naming it — which is easy to undo by adding a RemoveFolder in a later
	// change, so it is asserted here rather than left to a comment.
	for _, forbidden := range []string{"<RemoveFolder", "<RemoveFile", "<CustomAction"} {
		if strings.Contains(wxs, forbidden) {
			t.Errorf("dtp-agent.wxs uses %s; uninstalling must not be able to reach the agent's keypair", forbidden)
		}
	}
}
