package sandbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func nativeFileID(file *os.File, _ os.FileInfo) (string, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return "", err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.NumberOfLinks != 1 || info.FileIndexHigh == 0 && info.FileIndexLow == 0 {
		return "", fmt.Errorf("persistent backing is not an unaliased regular file")
	}
	return fmt.Sprintf("%x:%08x%08x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow), nil
}

func openVolume(root *os.Root, path string) (*os.File, error) {
	full := filepath.Join(root.Name(), path)
	h, err := openWindowsLeaf(full, windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), full), nil
}

func openWindowsLeaf(path string, access uint32) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(name, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

func commitRecord(root *os.Root, temp, name string) error { return moveExclusive(root, temp, name) }

// MoveFileEx without MOVEFILE_REPLACE_EXISTING never overwrites a backing.
func moveExclusive(root *os.Root, temp, name string) error {
	src, err := windows.UTF16PtrFromString(filepath.Join(root.Name(), temp))
	if err != nil {
		return err
	}
	dst, err := windows.UTF16PtrFromString(filepath.Join(root.Name(), name))
	if err != nil {
		return err
	}
	return windows.MoveFileEx(src, dst, windows.MOVEFILE_WRITE_THROUGH)
}

// Windows doesn't expose directory fsync. For birth and reclaim the path
// transition itself uses the write-through native move above.
func syncPath(_ *os.Root, _ string) error { return nil }

// Standard Windows removal may clear the read-only attribute, weakening the
// original immutable image because NTFS hardlinks share file attributes.
// Delete only the private links without changing their backing object's mode.
func removeCacheLinks(root *os.Root, path string) error {
	info, err := root.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("run cache directory is not owned")
	}
	dir, err := root.OpenRoot(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	f, err := dir.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	for {
		entries, readErr := f.ReadDir(16)
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			} // Only the GVX ephemeral staging directory.
			if !entry.Type().IsRegular() {
				return errors.New("unexpected run cache object")
			}
			if err := unlinkReadOnly(filepath.Join(dir.Name(), entry.Name())); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func unlinkReadOnly(path string) error {
	h, err := openWindowsLeaf(path, windows.DELETE|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	var attrs windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &attrs); err != nil {
		return err
	}
	if attrs.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return errors.New("unexpected linked cache object")
	}
	const fileDispositionInfoEx = 21
	const deletePOSIXIgnoreReadonly = 0x01 | 0x02 | 0x10
	disposition := uint32(deletePOSIXIgnoreReadonly)
	return windows.SetFileInformationByHandle(h, fileDispositionInfoEx, (*byte)(unsafe.Pointer(&disposition)), uint32(unsafe.Sizeof(disposition)))
}
