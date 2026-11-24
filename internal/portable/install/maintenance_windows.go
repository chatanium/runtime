package install

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/thirdscam/chatanium/internal/portable/process"
	"golang.org/x/sys/windows"
)

func checkMaintenanceDirectory(_, child *os.Root) error {
	return process.CheckPrivateDir(child.Name())
}

// The file handles have already passed the reparse-point check. Windows
// directory mount points are also reparse points and are refused at open.
func checkMaintenanceMount(_ *os.Root, _ *os.File) error { return nil }

func matchMaintenanceMode(actual, expected fs.FileMode) bool {
	return actual.Perm()&0200 == expected.Perm()&0200
}

func allowMaintenanceUnlink(f *os.File, info fs.FileInfo) error {
	if info.Mode().Perm()&0200 == 0 {
		return f.Chmod(0600)
	}
	return nil
}

func maintenanceHandleIdentity(f *os.File) (string, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return "", err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileIndexHigh == 0 && info.FileIndexLow == 0 {
		return "", errors.New("unrecognized native directory identity")
	}
	return fmt.Sprintf("%x:%08x%08x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow), nil
}

func publishMaintenanceCode(root, _ *os.Root, from, to string) error {
	src, err := windows.UTF16PtrFromString(filepath.Join(root.Name(), from))
	if err != nil {
		return err
	}
	dst, err := windows.UTF16PtrFromString(filepath.Join(root.Name(), to))
	if err != nil {
		return err
	}
	return windows.MoveFileEx(src, dst, windows.MOVEFILE_WRITE_THROUGH)
}
