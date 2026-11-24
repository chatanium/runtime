//go:build linux || (darwin && arm64)

package discordbackend

import (
	"errors"
	"os"
	"runtime"
	"syscall"

	"github.com/thirdscam/chatanium/internal/portable/process"
	"golang.org/x/sys/unix"
)

const ownershipReadFlags = unix.O_NONBLOCK

func checkOwnershipDirectory(path string, info os.FileInfo) error {
	if runtime.GOOS == "darwin" {
		return process.CheckPrivateDir(path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0700 {
		return errors.New("Discord ownership directory must be private and owned by the worker")
	}
	return nil
}

func checkOwnershipFile(file *os.File) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("Discord ownership file is not an owned, unlinked-from-elsewhere regular file")
	}
	if stat.Mode&07777 != 0600 {
		// Legacy SQLite versions could create a database before its original
		// path-based chmod. Repair only the exact file we own before SQLite opens it.
		if err := file.Chmod(0600); err != nil {
			return err
		}
	}
	return process.CheckPrivateFileACL(file)
}
