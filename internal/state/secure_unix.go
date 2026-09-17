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
