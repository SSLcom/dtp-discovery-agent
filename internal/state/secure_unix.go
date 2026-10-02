//go:build !windows

package state

import (
	"fmt"
	"os"
)

// secure narrows a path's permissions to exactly `want`, and says which path it
// was if it cannot.
func secure(path string, want os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Mode().Perm() == want {
		return nil
	}
	if err := os.Chmod(path, want); err != nil {
		return fmt.Errorf("securing %s: %w", path, err)
	}
	return nil
}

// secureReadable opens the public status directory to every local user for
// reading. Only the Windows service publishes one today; this exists so the
// package builds and tests the same everywhere.
func secureReadable(dir string) error {
	if err := os.Chmod(dir, 0o755); err != nil {
		return fmt.Errorf("securing %s: %w", dir, err)
	}
	return nil
}
