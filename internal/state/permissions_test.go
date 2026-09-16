package state

import (
	"runtime"
	"testing"
)

// requireUnixPermissions skips a test that turns on the Unix permission model.
//
// Windows has no mode bits. os.Chmod there can only toggle the read-only
// attribute, Go reports every file as 0666, and a file "chmodded" to 0000 stays
// perfectly readable — so an assertion about a mode is an assertion about
// nothing.
//
// THE GAP THIS LEAVES IS REAL, AND SKIPPING THE TEST DOES NOT CLOSE IT. The
// agent protects its own private key with a 0600 chmod and its state directory
// with 0700. On Windows both calls succeed and neither does anything, so the
// key is left with whatever the parent directory's ACL grants — which under
// %ProgramData% usually includes read access for every local user. Protecting it
// properly there means setting an ACL, which is not built. It is written down in
// the README under what is not done, rather than left implied by a green suite.
func requireUnixPermissions(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix permission bits; see the note in permissions_test.go")
	}
}
