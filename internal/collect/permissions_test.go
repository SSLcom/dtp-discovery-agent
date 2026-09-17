package collect

import (
	"os"
	"runtime"
	"testing"
)

// requireUnixPermissions skips a test that turns on the Unix permission model.
//
// Windows has no mode bits: os.Chmod can only toggle the read-only attribute,
// Go reports every file as 0666, and a file "chmodded" to 0000 stays perfectly
// readable. A test that asserts on a mode there is asserting on nothing.
//
// What this skips is a way of CHECKING, not a guarantee. The file modes this
// collector reports are Unix ones and simply have no Windows meaning — a
// member reading a portfolio does not need to be told every file there is
// 0666. Where a mode carries a real guarantee, which is the agent's own private
// key, Windows gets an ACL instead and internal/state/secure_windows_test.go
// checks it in that platform's own terms.
func requireUnixPermissions(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix permission bits; see the note in permissions_test.go")
	}
}

// requireUnprivileged skips a test that depends on being REFUSED access.
func requireUnprivileged(t *testing.T) {
	t.Helper()
	requireUnixPermissions(t)
	if os.Geteuid() == 0 {
		t.Skip("root can read anything, so a refusal cannot be shown here")
	}
}
