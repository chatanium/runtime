package ipcpath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/thirdscam/chatanium/internal/portable/process"
)

// RemoveWorkerDirectory is called under the installation lock, after native
// worker exit or a verified new boot. Never recurse into an unknown entry.
func RemoveWorkerDirectory(leaf string) error {
	if _, err := os.Lstat(leaf); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := process.CheckPrivateDir(leaf); err != nil {
		return err
	}
	entries, err := os.ReadDir(leaf)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(leaf, name)
		switch {
		case name == "worker" || name == "stop":
			if entry.IsDir() {
				return fmt.Errorf("unexpected worker endpoint directory: %s", name)
			}
		case strings.HasPrefix(name, "plugin-dir") && entry.IsDir():
			if err := process.CheckPrivateDir(path); err != nil {
				return err
			}
			if err := os.Remove(filepath.Join(path, "s")); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		default:
			return fmt.Errorf("unrecognized worker control entry: %s", name)
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Remove(leaf)
}
