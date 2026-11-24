package upload

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/thirdscam/chatanium/internal/portable/process"
	"golang.org/x/sys/windows"
)

func openSpool(ctx context.Context, management string, portable bool) (_ *spool, result error) {
	if ctx == nil || ctx.Err() != nil || process.CheckPrivateDir(management) != nil {
		return nil, invalid()
	}
	if err := process.CheckPrivateDir(filepath.Join(management, "uploads")); err != nil {
		return nil, invalid()
	}
	path, err := windows.UTF16PtrFromString(management)
	if err != nil {
		return nil, invalid()
	}
	parent, err := windows.CreateFile(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.FILE_TRAVERSE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, internal()
	}
	managementFile, err := checkedSpoolFile(parent, management, true)
	if err != nil {
		return nil, err
	}
	defer managementFile.Close()

	directory, err := openSpoolEntry(parent, "uploads", windows.FILE_LIST_DIRECTORY|windows.FILE_TRAVERSE, windows.FILE_OPEN, true)
	if err != nil {
		return nil, internal()
	}
	s := &spool{directory: directory}
	defer func() {
		if result != nil {
			s.close()
		}
	}()
	s.lock, err = openSpoolEntry(windows.Handle(directory.Fd()), ".owner", windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_OPEN_IF, false)
	if err != nil {
		return nil, internal()
	}
	var offset windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(s.lock.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &offset); err != nil {
		return nil, internal()
	}
	if err := s.recover(ctx, portable); err != nil {
		return nil, err
	}
	return s, nil
}

// Entries are opened relative to the held directory handle, without following
// reparse points and without delete sharing. All names are generated locally.
func openSpoolEntry(parent windows.Handle, name string, access, creation uint32, directory bool) (*os.File, error) {
	entry, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: parent,
		ObjectName: entry, Attributes: windows.OBJ_CASE_INSENSITIVE,
	}
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
	if directory {
		options |= windows.FILE_DIRECTORY_FILE
	} else {
		options |= windows.FILE_NON_DIRECTORY_FILE
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		&attributes, &status, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, creation, options, 0, 0)
	if err != nil {
		return nil, err
	}
	return checkedSpoolFile(handle, name, directory)
}

func checkedSpoolFile(handle windows.Handle, name string, directory bool) (*os.File, error) {
	file := os.NewFile(uintptr(handle), name)
	var info windows.ByHandleFileInformation
	err := windows.GetFileInformationByHandle(handle, &info)
	if err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || !directory && info.NumberOfLinks != 1 ||
		process.CheckPrivateFileACL(file) != nil {
		file.Close()
		return nil, invalid()
	}
	return file, nil
}

func (s *spool) create(name string) (*os.File, error) {
	file, err := openSpoolEntry(windows.Handle(s.directory.Fd()), name, windows.GENERIC_WRITE, windows.FILE_CREATE, false)
	if err != nil {
		return nil, internal()
	}
	return file, nil
}

func (s *spool) open(name string) (*os.File, error) {
	file, err := openSpoolEntry(windows.Handle(s.directory.Fd()), name, windows.GENERIC_READ, windows.FILE_OPEN, false)
	if err != nil {
		return nil, internal()
	}
	return file, nil
}

func (s *spool) removeOrphan(name string) error { return s.unlink(name, false) }
func (s *spool) remove(name string) error       { return s.unlink(name, true) }

func (s *spool) unlink(name string, missingOK bool) error {
	file, err := openSpoolEntry(windows.Handle(s.directory.Fd()), name, windows.DELETE, windows.FILE_OPEN, false)
	if missingOK && errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return internal()
	}
	// Commit sets FILE_ATTRIBUTE_READONLY. Delete that exact pinned file without
	// first unsealing it by a pathname. An outstanding reader denies delete access.
	flags := uint32(windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_POSIX_SEMANTICS | windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE)
	err = windows.SetFileInformationByHandle(windows.Handle(file.Fd()), windows.FileDispositionInfoEx, (*byte)(unsafe.Pointer(&flags)), uint32(unsafe.Sizeof(flags)))
	if closeErr := file.Close(); err != nil || closeErr != nil {
		return internal()
	}
	return nil
}
