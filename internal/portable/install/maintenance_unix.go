//go:build linux || darwin

package install

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

func checkMaintenanceDirectory(parent, child *os.Root) error {
	f, err := child.Open(".")
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
			err = errors.New("maintenance directory is not owned by the installation user")
		}
	}
	if err == nil {
		err = checkMaintenanceMount(parent, f)
	}
	return errors.Join(err, f.Close())
}

func matchMaintenanceMode(actual, expected fs.FileMode) bool { return actual == expected }

func allowMaintenanceUnlink(_ *os.File, _ fs.FileInfo) error { return nil }

func maintenanceHandleIdentity(f *os.File) (string, error) {
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Ino == 0 {
		return "", errors.New("unrecognized native directory identity")
	}
	return fmt.Sprintf("%x:%x", st.Dev, st.Ino), nil
}

func publishMaintenanceCode(root, stage *os.Root, from, to string) error {
	if err := root.Rename(from, to); err != nil {
		return err
	}
	return errors.Join(syncDirectory(stage), syncDirectory(root))
}
