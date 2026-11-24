package install

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func checkMaintenanceMount(parent *os.Root, child *os.File) error {
	p, err := parent.Open(".")
	if err != nil {
		return err
	}
	defer p.Close()
	var a, b unix.Statx_t
	if err := unix.Statx(int(p.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &a); err != nil {
		return err
	}
	if err := unix.Statx(int(child.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &b); err != nil {
		return err
	}
	if a.Mask&b.Mask&unix.STATX_MNT_ID == 0 || a.Mnt_id != b.Mnt_id {
		return errors.New("refusing to cross an unverified installation mount")
	}
	return nil
}
