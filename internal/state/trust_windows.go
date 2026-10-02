//go:build windows

package state

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// trustDir decides whether a state directory is the agent's own before
// anything is read out of it, and takes it back if it safely can.
//
// THE ATTACK THIS CLOSES. %ProgramData% lets every local user create folders,
// and whoever creates one OWNS it. So a standard user can make DTP\agent
// before the agent is installed, drop in an agent.key whose private half they
// keep, and wait: the service would tighten the ACL — which changes nothing
// for an owner, who can always rewrite the ACL back — and then adopt the key as
// its identity, letting that user report as this machine for as long as DTP
// trusts it. The same ownership let them swap a subdirectory for a junction
// and have SYSTEM rewrite the ACL of whatever it pointed at. Setting the ACL
// was never enough; the OWNER is what decides who can undo it.
//
// So, for a privileged process (the service, or an elevated prompt):
//   - a reparse point (junction or symlink) where the directory, or the DTP
//     folder above the default one, should be is refused outright;
//   - a directory owned by an administrator, SYSTEM or TrustedInstaller is
//     trusted, and so is everything in it;
//   - a directory owned by anyone else is taken back — owner set to the
//     Administrators group — ONLY IF IT HOLDS NOTHING THE AGENT WOULD TRUST: a
//     key or a configuration found there cannot be told from a planted one, so
//     it is refused, with the sentence that says what to do.
//
// THAT LAST CHECK ONLY NARROWS THE HOLE. Its owner can still write into the
// directory between the check and the claim, or later through a handle opened
// earlier. What closes it is readTrusted, below: every file the agent believes
// is judged by its own owner at the moment it is read.
//
// An unprivileged process cannot take anything back and has nothing to
// protect: a directory it owns is its own (a test, or `--state` pointing
// somewhere private), and a directory another user owns is refused.
func trustDir(dir string) error {
	privileged := windows.GetCurrentProcessToken().IsElevated()

	if isDefaultDir(dir) {
		parent := filepath.Dir(dir)
		if err := refuseReparse(parent); err != nil {
			return err
		}
		if privileged {
			// The DTP folder holds nothing but the state directory, so it can
			// always be taken back. Its owner could otherwise rename `agent`
			// out from under the service and put a junction in its place.
			if err := claim(parent); err != nil {
				return err
			}
			if err := secure(parent, dirPerm); err != nil {
				return err
			}
		}
	}

	if err := refuseReparse(dir); err != nil {
		return err
	}
	owner, err := ownerOf(dir)
	if err != nil {
		return err
	}
	if trustedOwner(owner) {
		// An administrator's own account — every v0.3 directory enrolled from
		// an elevated prompt. Believed, and handed to the group so the next
		// open does not have to look that account's groups up again.
		if privileged && !isGroupOwned(owner) {
			_ = setOwnerAdmins(dir)
		}
		return nil
	}

	if !privileged {
		if self, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil && owner.Equals(self.User.Sid) {
			return nil
		}
		return fmt.Errorf("state directory %s belongs to %s, not to this user or an administrator; "+
			"run from an administrator prompt", dir, accountName(owner))
	}

	for _, name := range []string{"agent.key", "config.json"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			return fmt.Errorf("state directory %s was created by %s, not by an administrator, "+
				"and already holds %s — which cannot be told apart from one planted there, so it will not be used. "+
				"Delete %s and enroll again from an administrator prompt", dir, accountName(owner), name, dir)
		}
	}
	return claim(dir)
}

// claim makes the Administrators group the owner of a path. Needs the
// take-ownership privilege, which an elevated administrator and SYSTEM hold but
// do not have switched on.
func claim(path string) error {
	owner, err := ownerOf(path)
	if err != nil {
		return err
	}
	if trustedOwner(owner) {
		return nil
	}
	if err := setOwnerAdmins(path); err != nil {
		return fmt.Errorf("taking ownership of %s from %s: %w", path, accountName(owner), err)
	}
	return nil
}

func setOwnerAdmins(path string) error {
	if err := enablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege"); err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil)
}

// refuseReparse fails if the path is a junction, a symlink, or any other
// reparse point. Following one is how a write meant for this directory lands
// somewhere else, with SYSTEM's rights.
func refuseReparse(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil
		}
		return fmt.Errorf("checking %s: %w", path, err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is a junction or link, not a directory; the agent will not follow it. "+
			"Remove it and run the agent again", path)
	}
	return nil
}

func isReparse(path string) bool { return refuseReparse(path) != nil && exists(path) }

func exists(path string) bool { _, err := os.Lstat(path); return err == nil }

func ownerOf(path string) (*windows.SID, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("reading the owner of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, fmt.Errorf("reading the owner of %s: %w", path, err)
	}
	return owner, nil
}

// trustedInstaller is the service SID Windows itself installs files as.
const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// trustedOwner reports whether an owner is one the agent may believe: SYSTEM,
// TrustedInstaller, the Administrators group — or ANY ACCOUNT THAT IS AN
// ADMINISTRATOR.
//
// THE LAST CLAUSE IS NOT A CONVENIENCE. Who owns what an administrator
// creates depends on a security policy ("Default owner for objects created by
// members of the Administrators group"), which varies by edition and estate —
// measured on a GitHub Windows Server runner, it is the group. Where it is
// "Object creator", and wherever an administrator enrolled v0.3 from an
// UNELEVATED prompt (which v0.3 allowed), the key is owned by a person, and an
// owner check that knew only the group SID would call it planted and stop
// those agents reporting at the upgrade. What the planted-key attack needs is
// a file a STANDARD user wrote; an administrator could replace the key anyway.
func trustedOwner(sid *windows.SID) bool {
	for _, which := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		if w, err := windows.CreateWellKnownSid(which); err == nil && sid.Equals(w) {
			return true
		}
	}
	if ti, err := windows.StringToSid(trustedInstaller); err == nil && sid.Equals(ti) {
		return true
	}
	return isAdministrator(sid)
}

var (
	authz                              = windows.NewLazySystemDLL("authz.dll")
	procAuthzInitializeResourceManager = authz.NewProc("AuthzInitializeResourceManager")
	procAuthzInitializeContextFromSid  = authz.NewProc("AuthzInitializeContextFromSid")
	procAuthzGetInformationFromContext = authz.NewProc("AuthzGetInformationFromContext")
	procAuthzFreeContext               = authz.NewProc("AuthzFreeContext")
	procAuthzFreeResourceManager       = authz.NewProc("AuthzFreeResourceManager")
)

// isAdministrator asks Windows whether an account is a member of the local
// Administrators group, directly or through any nesting of groups — the AuthZ
// API computes the account's full group list the way a logon would, which a
// walk of the group's direct members would not (domain and Entra groups are
// how most estates grant admin).
//
// FAILS CLOSED. An account whose groups cannot be computed — a domain account
// with no domain controller in reach — is not believed, and the agent says so.
// That costs a report until the controller is back, once: a file that passes
// is handed to the Administrators group, and the group needs no lookup.
func isAdministrator(sid *windows.SID) bool {
	const (
		authzRMFlagNoAudit       = 0x1
		authzContextInfoGroupSid = 2
	)
	var rm windows.Handle
	if r, _, _ := procAuthzInitializeResourceManager.Call(authzRMFlagNoAudit, 0, 0, 0, 0, uintptr(unsafe.Pointer(&rm))); r == 0 {
		return false
	}
	defer procAuthzFreeResourceManager.Call(uintptr(rm))

	var ctx windows.Handle
	var none windows.LUID
	if r, _, _ := procAuthzInitializeContextFromSid.Call(0, uintptr(unsafe.Pointer(sid)), uintptr(rm), 0,
		uintptr(*(*uint64)(unsafe.Pointer(&none))), 0, uintptr(unsafe.Pointer(&ctx))); r == 0 {
		return false
	}
	defer procAuthzFreeContext.Call(uintptr(ctx))

	var size uint32
	procAuthzGetInformationFromContext.Call(uintptr(ctx), authzContextInfoGroupSid, 0, uintptr(unsafe.Pointer(&size)), 0)
	if size == 0 {
		return false
	}
	buf := make([]byte, size)
	if r, _, _ := procAuthzGetInformationFromContext.Call(uintptr(ctx), authzContextInfoGroupSid, uintptr(size),
		uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&buf[0]))); r == 0 {
		return false
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	for _, g := range (*windows.Tokengroups)(unsafe.Pointer(&buf[0])).AllGroups() {
		if g.Sid.Equals(admins) {
			return true
		}
	}
	return false
}

func accountName(sid *windows.SID) string {
	if account, domain, _, err := sid.LookupAccount(""); err == nil {
		if domain != "" {
			return domain + `\` + account
		}
		return account
	}
	return sid.String()
}

func isDefaultDir(dir string) bool {
	return strings.EqualFold(filepath.Clean(dir), filepath.Clean(DefaultDir()))
}

// enablePrivileges switches on privileges this token holds but has off.
// Best effort: a privilege the token does not hold simply stays off, and the
// call that needed it fails with an error that says so.
func enablePrivileges(names ...string) error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	for _, name := range names {
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
			return err
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		_ = windows.AdjustTokenPrivileges(token, false, &tp, uint32(unsafe.Sizeof(tp)), nil, nil)
	}
	return nil
}

// readTrusted reads a file the agent will BELIEVE — its key, its
// configuration, its memory of the last run — and refuses one that an
// untrusted account owns.
//
// THIS IS WHAT ACTUALLY CLOSES THE PLANTED-KEY HOLE; trustDir only narrows it.
// A user who created the directory can write into it right up to the moment
// it is taken back, and through a handle opened before then, even after — so
// no check of the directory, at any one moment, can promise what it will hold
// when the key is read. The file's own owner can: whoever creates a file owns
// it, and a privileged writer here always hands what it writes to the
// administrators (see adopt). The owner is read through the same handle the
// bytes come from, so the file that was checked is the file that is read.
func readTrusted(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("reading the owner of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, fmt.Errorf("reading the owner of %s: %w", path, err)
	}
	if !acceptableOwner(owner) {
		return nil, fmt.Errorf("%s belongs to %s, not to an administrator — it may have been planted, and will not be used. "+
			"Delete %s and enroll again from an administrator prompt", path, accountName(owner), filepath.Dir(path))
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	// Believed, so handed to the group: a key owned by the administrator who
	// enrolled needs that person's group memberships looked up on every read
	// until it is, and a domain account's lookup can fail. Best effort.
	if windows.GetCurrentProcessToken().IsElevated() && !isGroupOwned(owner) {
		_ = setOwnerAdmins(path)
	}
	return raw, nil
}

func isGroupOwned(owner *windows.SID) bool {
	for _, which := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		if w, err := windows.CreateWellKnownSid(which); err == nil && owner.Equals(w) {
			return true
		}
	}
	ti, err := windows.StringToSid(trustedInstaller)
	return err == nil && owner.Equals(ti)
}

// acceptableOwner: an administrator, SYSTEM or TrustedInstaller for a
// privileged process; for an unprivileged one, also itself — its own files in
// its own directory, which is all it can reach.
func acceptableOwner(owner *windows.SID) bool {
	if trustedOwner(owner) {
		return true
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		return false
	}
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && owner.Equals(self.User.Sid)
}

// adopt makes the administrators the owner of a file a privileged process has
// just written. Without it, a machine whose policy makes the CREATOR the owner
// of what an administrator creates would leave the key owned by whichever
// admin enrolled — and the service, reading it as SYSTEM, would refuse its own
// key.
func adopt(path string) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil
	}
	return setOwnerAdmins(path)
}
