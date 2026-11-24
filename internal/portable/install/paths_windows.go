package install

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const readFileFlags = os.O_RDONLY

func dataHome() (string, error) {
	path, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil {
		return "", err
	}
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' {
		return "", errors.New("portable LocalAppData must be on a local drive")
	}
	return path, nil
}

func safeEntry(info fs.FileInfo) bool {
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && data.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 && info.Mode()&fs.ModeSymlink == 0
}

func ownedFile(info fs.FileInfo) bool { return info.Mode().IsRegular() && safeEntry(info) }

func checkFileHandle(file *os.File) error {
	handle := windows.Handle(file.Fd())
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.NumberOfLinks != 1 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("refusing a linked or reparsed file")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	security, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := security.Owner()
	if err != nil || !owner.Equals(user.User.Sid) {
		return errors.New("file is not owned by the current user")
	}
	acl, _, err := security.DACL()
	if err != nil || acl == nil {
		return errors.New("file has no protected access list")
	}
	const write = windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_ATTRIBUTES | windows.FILE_WRITE_EA
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, &ace); err != nil {
			return err
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("file has an unsupported access rule")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(user.User.Sid) && !sid.IsWellKnown(windows.WinLocalSystemSid) && !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) && ace.Mask&write != 0 {
			return errors.New("file grants access to another account")
		}
	}
	return nil
}

// Windows does not expose directory fsync. Durable metadata publication uses
// a native write-through replacement after syncing the file contents.
func syncDirectory(_ *os.Root) error { return nil }

func replaceFile(root *os.Root, from, to string) error {
	fromRoot, fromLeaf, closeFrom, err := ownedParent(root, filepath.ToSlash(from))
	if err != nil {
		return err
	}
	defer closeFrom()
	toRoot, toLeaf, closeTo, err := ownedParent(root, filepath.ToSlash(to))
	if err != nil {
		return err
	}
	defer closeTo()
	src, err := windows.UTF16PtrFromString(filepath.Join(fromRoot.Name(), fromLeaf))
	if err != nil {
		return err
	}
	dst, err := windows.UTF16PtrFromString(filepath.Join(toRoot.Name(), toLeaf))
	if err != nil {
		return err
	}
	return windows.MoveFileEx(src, dst, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
