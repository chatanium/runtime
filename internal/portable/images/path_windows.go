package images

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

func plainEntry(info fs.FileInfo) bool {
	attr, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && attr.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 && info.Mode()&fs.ModeSymlink == 0
}

func renameImageNoReplace(root *os.Root, from, to string) error {
	// The installation owner lock and checked non-reparse parents pin these
	// paths. MOVEFILE_WRITE_THROUGH requests durability; there is no replace,
	// delayed operation, or cross-volume copy flag.
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
