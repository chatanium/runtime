//go:build linux || darwin

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func nativeFileID(_ *os.File, info os.FileInfo) (string, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Ino == 0 || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("persistent backing is not an owner-only, unaliased regular file")
	}
	return fmt.Sprintf("%x:%x", st.Dev, st.Ino), nil
}

func openVolume(root *os.Root, path string) (*os.File, error) {
	return root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

func commitRecord(root *os.Root, temp, name string) error {
	if err := root.Rename(temp, name); err != nil {
		return err
	}
	if err := syncPath(root, "."); err != nil {
		return err
	}
	// Persist the run directory itself before creating a control socket in
	// an external temporary directory.
	parent, err := os.Open(filepath.Dir(root.Name()))
	if err != nil {
		return err
	}
	return errors.Join(parent.Sync(), parent.Close())
}

// moveExclusive is used for both birth publication and retirement into the
// private run directory. The syncs make absence/presence durable before the
// store commits a transition based on that path.
func moveExclusive(root *os.Root, from, to string) error {
	src, err := root.Open(filepath.Dir(from))
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := root.Open(filepath.Dir(to))
	if err != nil {
		return err
	}
	defer dst.Close()
	if err := renameNoReplace(int(src.Fd()), filepath.Base(from), int(dst.Fd()), filepath.Base(to)); err != nil {
		return err
	}
	return errors.Join(dst.Sync(), src.Sync())
}

func syncPath(root *os.Root, path string) error {
	dir, err := root.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func removeCacheLinks(_ *os.Root, _ string) error { return nil }
