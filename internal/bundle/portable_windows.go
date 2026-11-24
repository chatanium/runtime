package bundle

import (
	"io/fs"
	"os"
	"syscall"
)

func validPortableNode(info fs.FileInfo, expected fs.FileMode) bool {
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok || data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false
	}
	// Directory ownership and its user-only DACL are established by the
	// installer before it passes the directory handle. Windows chmod only
	// controls the read-only attribute, not the Unix execute/mode bits.
	return expected&0200 != 0 || data.FileAttributes&syscall.FILE_ATTRIBUTE_READONLY != 0
}

func validPortableFileHandle(file *os.File, _ fs.FileInfo) bool {
	var data syscall.ByHandleFileInformation
	return syscall.GetFileInformationByHandle(syscall.Handle(file.Fd()), &data) == nil && data.NumberOfLinks == 1
}

// Windows FlushFileBuffers does not support directory handles. Code files
// themselves are synced; the installer owns publication and directory DACLs.
func syncPortableDirectory(_ *os.Root, _ string) error { return nil }
