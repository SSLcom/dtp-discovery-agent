//go:build windows

package state

import (
	"errors"
	"fmt"
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
	if err := enablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege"); err != nil {
		return fmt.Errorf("taking ownership of %s: %w", path, err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
		return fmt.Errorf("taking ownership of %s from %s: %w", path, accountName(owner), err)
	}
	return nil
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

func trustedOwner(sid *windows.SID) bool {
	for _, which := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		if w, err := windows.CreateWellKnownSid(which); err == nil && sid.Equals(w) {
			return true
		}
	}
	if ti, err := windows.StringToSid(trustedInstaller); err == nil && sid.Equals(ti) {
		return true
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
