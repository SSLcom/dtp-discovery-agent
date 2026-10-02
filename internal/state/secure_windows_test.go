//go:build windows

package state

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ace is one entry of a path's access control list, in the terms this test
// cares about: who, and whether the list it came from is detached from the
// parent's permissions.
type ace struct {
	sid  *windows.SID
	mask windows.ACCESS_MASK
}

func readDACL(t *testing.T, path string) (protected bool, aces []ace) {
	t.Helper()

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("reading the permissions of %s: %v", path, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("reading the control flags of %s: %v", path, err)
	}
	protected = control&windows.SE_DACL_PROTECTED != 0

	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("reading the access list of %s: %v", path, err)
	}
	if dacl == nil {
		// A NULL DACL grants everyone everything. It is the worst possible
		// outcome and it is not an empty list.
		t.Fatalf("%s has no access list at all, which grants everyone full control", path)
	}

	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var entry *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &entry); err != nil {
			t.Fatalf("reading entry %d of %s: %v", i, path, err)
		}
		aces = append(aces, ace{
			sid:  (*windows.SID)(unsafe.Pointer(&entry.SidStart)),
			mask: entry.Mask,
		})
	}
	return protected, aces
}

func grants(aces []ace, sid *windows.SID) bool {
	for _, entry := range aces {
		if entry.sid.Equals(sid) {
			return true
		}
	}
	return false
}

func wellKnown(t *testing.T, which windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(which)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// openUpTo grants a trustee full control WITHOUT protecting the list, which is
// how a path ends up readable by everyone: an installer, a configuration tool,
// or simply inheriting from %ProgramData%.
func openUpTo(t *testing.T, path string, sid *windows.SID) {
	t.Helper()
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatalf("opening up %s for the test: %v", path, err)
	}
}

// THE TEST THIS FIX EXISTS FOR. A state directory that any user could read —
// which is what %ProgramData% gives you by default — must be closed when the
// agent opens it, not merely left alone because a chmod returned nil.
func TestAStateDirectoryAnyoneCouldReadIsClosed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	everyone := wellKnown(t, windows.WinWorldSid)
	openUpTo(t, dir, everyone)

	// Proving the setup worked, and NOT a formality: if granting Everyone
	// access had quietly failed, the assertion below would pass without the
	// agent having done anything at all.
	if _, aces := readDACL(t, dir); !grants(aces, everyone) {
		t.Fatal("the test could not open the directory up, so it cannot show that the agent closes it")
	}

	if _, err := Open(dir); err != nil {
		t.Fatal(err)
	}

	protected, aces := readDACL(t, dir)
	if grants(aces, everyone) {
		t.Error("every user on this machine can still read the directory holding the agent's private key")
	}
	// The flag that does the work. Three generous entries on a directory that
	// still inherits "Users: Read" from its parent protect nothing at all.
	if !protected {
		t.Error("the directory still inherits its parent's permissions, so closing it achieved nothing")
	}
}

func TestTheKeyFileIsClosedToOtherUsers(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadOrCreateKey(); err != nil {
		t.Fatal(err)
	}

	protected, aces := readDACL(t, filepath.Join(store.Dir(), "agent.key"))
	if !protected {
		t.Error("the key file still inherits its parent's permissions")
	}
	for _, open := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinWorldSid,             // Everyone
		windows.WinBuiltinUsersSid,      // Users
		windows.WinAuthenticatedUserSid, // Authenticated Users
	} {
		if grants(aces, wellKnown(t, open)) {
			t.Errorf("the private key is readable by %s", wellKnown(t, open))
		}
	}
	// Three at most, and fewer when the process runs as one of them.
	if len(aces) == 0 || len(aces) > 3 {
		t.Errorf("the key has %d access entries; it should name this agent, SYSTEM and the administrators", len(aces))
	}
}

// The other half, and the one that would turn a security fix into an outage: an
// access list that excludes everybody excludes the agent too. A key it cannot
// read is a fleet that stops reporting.
func TestTheAgentCanStillReadItsOwnKey(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.LoadOrCreateKey()
	if err != nil {
		t.Fatal(err)
	}

	// A second Store, as the next invocation of the binary would be — the
	// permissions have been applied by now, so this is the read that a locked
	// file would refuse.
	reopened, err := Open(store.Dir())
	if err != nil {
		t.Fatalf("reopening the state directory the agent just secured: %v", err)
	}
	loaded, err := reopened.LoadOrCreateKey()
	if err != nil {
		t.Fatalf("the agent locked itself out of its own key: %v", err)
	}
	if !created.Equal(loaded) {
		t.Error("a different key came back, so the first one was not readable")
	}
}

// SYSTEM has to be on the list whoever ran the agent. An administrator enrols
// by hand, and the service that starts afterwards runs as SYSTEM and has to be
// able to read the key that enrollment created.
func TestSystemCanReadTheKeyWhoeverCreatedIt(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadOrCreateKey(); err != nil {
		t.Fatal(err)
	}

	_, aces := readDACL(t, filepath.Join(store.Dir(), "agent.key"))
	if !grants(aces, wellKnown(t, windows.WinLocalSystemSid)) {
		t.Error("the service account cannot read the key, so the agent would stop reporting after a restart")
	}
}

// The public status is the one thing in the state directory every local user
// may read — and only read. Either half failing is a real bug: closed, and the
// notification-area icon can say nothing; writable, and any user can make every
// icon on the machine say whatever they like.
func TestThePublicStatusIsReadableByUsersAndWritableByNoneOfThem(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WritePublicStatus(&PublicStatus{Phase: PhaseNotEnrolled}); err != nil {
		t.Fatal(err)
	}
	users := wellKnown(t, windows.WinBuiltinUsersSid)

	for _, path := range []string{filepath.Dir(PublicStatusPath(store.Dir())), PublicStatusPath(store.Dir())} {
		_, aces := readDACL(t, path)
		found := false
		for _, entry := range aces {
			if !entry.sid.Equals(users) {
				continue
			}
			found = true
			// The generic rights are mapped to file-specific bits when the ACE
			// lands on a file, so check the bits that matter in both forms.
			const writes = windows.GENERIC_WRITE | windows.GENERIC_ALL | windows.FILE_WRITE_DATA |
				windows.FILE_APPEND_DATA | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER
			if entry.mask&writes != 0 {
				t.Errorf("Users can modify %s (mask %#x)", path, entry.mask)
			}
		}
		if !found {
			t.Errorf("Users cannot read %s, so the icon has nothing to show", path)
		}
	}

	// The parent must not have been opened up to make that work.
	if _, aces := readDACL(t, store.Dir()); grants(aces, users) {
		t.Error("publishing the status opened the directory holding the private key to Users")
	}
}

// Open re-secures the state directory every time, and a DACL set on a parent
// propagates to every child that is not protected. If the public directory were
// not protected, the next `dtp-agent status` would quietly close it again and
// the icon would go blank until the service next wrote.
func TestReopeningTheStateDirectoryKeepsThePublicStatusReadable(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WritePublicStatus(&PublicStatus{Phase: PhaseNotEnrolled}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(store.Dir()); err != nil {
		t.Fatal(err)
	}
	if _, aces := readDACL(t, PublicStatusPath(store.Dir())); !grants(aces, wellKnown(t, windows.WinBuiltinUsersSid)) {
		t.Error("re-securing the state directory took Users' read access off the public status")
	}
}
