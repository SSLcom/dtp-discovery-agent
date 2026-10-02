//go:build windows

package state

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("making a junction for the test: %v\n%s", err, out)
	}
	if !isReparse(link) {
		t.Fatal("the test's junction is not a reparse point, so it cannot show anything")
	}
}

func sddl(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

// A junction where the state directory should be would have the agent write
// its private key, and set its ACL, wherever the junction pointed.
func TestAJunctionInPlaceOfTheStateDirectoryIsRefused(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "elsewhere")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "agent")
	junction(t, link, target)
	before := sddl(t, target)

	if _, err := Open(link); err == nil || !strings.Contains(err.Error(), "junction") {
		t.Fatalf("opened a state directory that is a junction: %v", err)
	}
	if after := sddl(t, target); after != before {
		t.Errorf("refusing still rewrote the permissions of the junction's target:\nbefore %s\nafter  %s", before, after)
	}
}

// THE REDIRECT THE BLUE TEAM FOUND. Followed, the service would write a
// "Users may read" ACL onto whatever folder the junction named, every minute.
func TestAJunctionInPlaceOfThePublicDirectoryIsReplacedNotFollowed(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	junction(t, filepath.Join(store.Dir(), publicDirName), target)
	before := sddl(t, target)

	if err := store.WritePublicStatus(&PublicStatus{Phase: PhaseNotEnrolled}); err != nil {
		t.Fatal(err)
	}
	if isReparse(filepath.Join(store.Dir(), publicDirName)) {
		t.Error("the public directory is still a junction")
	}
	if _, err := os.Stat(filepath.Join(target, "status.json")); err == nil {
		t.Error("the status was written through the junction")
	}
	if after := sddl(t, target); after != before {
		t.Errorf("the junction's target had its permissions rewritten:\nbefore %s\nafter  %s", before, after)
	}
}

// giveTo makes another account the owner of a path, as a standard user who
// created it would be. Needs the restore privilege, so only an elevated test
// process can set this up — which is also the only kind that can take it back.
func giveTo(t *testing.T, path string, which windows.WELL_KNOWN_SID_TYPE) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated test process to make another account the owner")
	}
	if err := enablePrivileges("SeRestorePrivilege", "SeTakeOwnershipPrivilege"); err != nil {
		t.Fatal(err)
	}
	sid, err := windows.CreateWellKnownSid(which)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil); err != nil {
		t.Fatalf("making %s the owner for the test: %v", path, err)
	}
	if owner, _ := ownerOf(path); owner == nil || !owner.Equals(sid) {
		t.Fatal("the test could not change the owner, so it cannot show anything")
	}
}

// THE CRITICAL ONE. A key a standard user put in a directory they created
// before the install cannot be told from the agent's own — and adopting it
// hands that user the machine's identity in DTP.
func TestAKeyInADirectoryAnotherUserCreatedIsNotAdopted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.key"), []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	giveTo(t, dir, windows.WinBuiltinUsersSid)

	_, err := Open(dir)
	if err == nil || !strings.Contains(err.Error(), "cannot be told apart") {
		t.Fatalf("opened a state directory another account created, key and all: %v", err)
	}
}

// The benign version of the same thing, and the commonest: someone ran
// `dtp-agent` unelevated before installing, and it left an empty directory
// they own. Refusing that would strand the service; it is taken back.
func TestAnEmptyDirectoryAnotherUserCreatedIsTakenBack(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	giveTo(t, dir, windows.WinBuiltinUsersSid)

	if _, err := Open(dir); err != nil {
		t.Fatalf("an empty directory was not taken back: %v", err)
	}
	owner, err := ownerOf(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !trustedOwner(owner) {
		t.Errorf("the directory is still owned by %s", accountName(owner))
	}
}

// THE RACE BUGBOT FOUND. A user who created the directory can still drop a key
// into it after the directory check has passed — so the key is judged by its
// OWN owner when it is read, whatever the directory looked like earlier. This
// plants it inside a directory the agent already trusts: the state the race
// leaves behind.
func TestAKeyAnotherAccountOwnsIsRefusedWhenRead(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"agent.key", "config.json"} {
		path := filepath.Join(store.Dir(), name)
		if err := os.WriteFile(path, []byte("planted"), 0o600); err != nil {
			t.Fatal(err)
		}
		giveTo(t, path, windows.WinBuiltinUsersSid)
	}

	if _, err := store.LoadOrCreateKey(); err == nil || !strings.Contains(err.Error(), "may have been planted") {
		t.Errorf("a key another account owns was used: %v", err)
	}
	if _, err := store.LoadConfig(); err == nil || !strings.Contains(err.Error(), "may have been planted") {
		t.Errorf("a configuration another account owns was used: %v", err)
	}
}

// The other half: what the agent writes itself, it must still be able to read
// — including as SYSTEM after an administrator enrolled, on a machine whose
// policy makes the creator, not the Administrators group, the owner.
func TestWhatAPrivilegedAgentWritesIsOwnedByTheAdministrators(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("only a privileged process hands its files to the administrators")
	}
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadOrCreateKey(); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveConfig(&Config{ServerURL: "https://x", AccountID: "a"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"agent.key", "config.json"} {
		owner, err := ownerOf(filepath.Join(store.Dir(), name))
		if err != nil {
			t.Fatal(err)
		}
		if !trustedOwner(owner) {
			t.Errorf("%s is owned by %s; the service could refuse its own file", name, accountName(owner))
		}
	}
}
