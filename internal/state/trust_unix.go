//go:build !windows

package state

// On Unix the packages create the state directory as root under /var/lib or
// /Library, which no unprivileged user can write, and the 0700 secure() sets
// is enforced by the owner it already has. Nothing to take back.
func trustDir(string) error { return nil }

func isReparse(string) bool { return false }
