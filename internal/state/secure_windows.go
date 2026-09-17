//go:build windows

package state

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// secure puts an ACL on a path that lets this agent, the system and the
// administrators read it, and nobody else.
//
// WHY THIS FILE EXISTS: `want` is a POSIX mode, and Windows has none. os.Chmod
// there can only toggle the read-only attribute — it SUCCEEDS and changes
// nothing about who may read the file. So for one release the agent wrote its
// private key with a 0600 that did nothing, and the key was left with whatever
// its parent directory granted. Under %ProgramData%, which is where the package
// puts it, that normally includes read access for every local user: any account
// on the machine could take the key and impersonate the agent to DTP until
// somebody noticed and revoked it.
//
// BREAKING INHERITANCE IS THE PART THAT MATTERS. Adding three generous ACEs to a
// file that still inherits "Users: Read" from %ProgramData% protects nothing —
// the inherited entry is still there and still grants the read. The whole point
// of this function is the PROTECTED flag below, which detaches the object from
// its parent's permissions; the entries it then installs are what stops the
// agent locking itself out.
func secure(path string, want os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	dacl, err := ownerOnlyDACL(info.IsDir())
	if err != nil {
		return fmt.Errorf("securing %s (intended %04o): %w", path, want.Perm(), err)
	}

	// PROTECTED_DACL_SECURITY_INFORMATION detaches this object from its
	// parent's permissions. Without it, everything else here is decoration.
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		return fmt.Errorf("securing %s (intended %04o): %w", path, want.Perm(), err)
	}
	return nil
}

// ownerOnlyDACL grants full control to three identities and names no others.
//
//   - THIS PROCESS'S OWN USER, because the ACL replaces everything inherited and
//     the agent would otherwise lock itself out of its own key. It covers both
//     the service running as a machine account and an administrator enrolling by
//     hand.
//   - SYSTEM, because the service runs as it. An administrator who enrols
//     interactively creates the key under their own account, and the service
//     that starts afterwards must still be able to read it.
//   - ADMINISTRATORS, deliberately. An administrator can take ownership of any
//     file on the machine and grant themselves whatever they like, so excluding
//     them buys no security at all — it only breaks backup, migration and
//     support, and leaves a file whose permissions look stricter than they are.
func ownerOnlyDACL(isDir bool) (*windows.ACL, error) {
	// A directory's entries must inherit the restriction, or a key file created
	// inside it afterwards picks up nothing and the protection lasts exactly as
	// long as the directory is empty.
	inheritance := uint32(windows.NO_INHERITANCE)
	if isDir {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("reading this process's own user: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, fmt.Errorf("resolving the SYSTEM account: %w", err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, fmt.Errorf("resolving the Administrators group: %w", err)
	}

	var (
		entries []windows.EXPLICIT_ACCESS
		already []*windows.SID
	)
	for _, sid := range []*windows.SID{user.User.Sid, system, administrators} {
		// Running as SYSTEM makes the first two the same account. A duplicate
		// ACE is harmless but it makes the permissions dialog lie about how
		// many identities have access, and this file is going to be read by
		// somebody auditing exactly that.
		if containsSID(already, sid) {
			continue
		}
		already = append(already, sid)
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}

	// Built from the entries alone, with no ACL to merge into: anything already
	// on the object is REPLACED rather than added to, which is what makes this
	// work on a key that a previous version left open.
	return windows.ACLFromEntries(entries, nil)
}

func containsSID(haystack []*windows.SID, needle *windows.SID) bool {
	for _, sid := range haystack {
		if sid.Equals(needle) {
			return true
		}
	}
	return false
}
