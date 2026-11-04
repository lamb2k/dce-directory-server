//go:build !windows

package dcedirectory

import (
	"os"
	"path/filepath"
)

func replaceApprovalFile(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(to))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
