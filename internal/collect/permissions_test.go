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
// THE PRODUCT CONSEQUENCE IS REAL AND IS NOT FIXED BY SKIPPING A TEST. The
// agent protects its own private key with a 0600 chmod, which on Windows does
// nothing at all; protecting it there needs an ACL, and that is not built. It is
// recorded in the README under what is not done rather than hidden behind a
// green suite.
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
