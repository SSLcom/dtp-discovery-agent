//go:build !windows

package state

import "os"

// On Unix the packages create the state directory as root under /var/lib or
// /Library, which no unprivileged user can write, and the 0700 secure() sets
// is enforced by the owner it already has. Nothing to take back.
func trustDir(string) error { return nil }

func isReparse(string) bool { return false }

// Unix files are guarded by the root-owned 0700 directory they sit in.
func readTrusted(path string) ([]byte, error) { return os.ReadFile(path) }

func adopt(string) error { return nil }
