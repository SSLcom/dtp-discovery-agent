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
// THE GUARANTEE ITSELF IS NOT SKIPPED, only this way of checking it. What a
// 0600 means on Unix, an ACL means on Windows, and secure_windows_test.go
// asserts the same property in the terms that platform actually has: a
// directory any user could read is closed, the list is detached from its
// parent's, and the agent can still read its own key.
func requireUnixPermissions(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows expresses this as an ACL; see secure_windows_test.go")
	}
}
