//go:build linux || darwin

package install

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

const readFileFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK

func dataHome() (string, error) {
	if runtime.GOOS == "linux" {
		if value := os.Getenv("XDG_DATA_HOME"); value != "" {
			return value, nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support"), nil
	}
	return filepath.Join(home, ".local", "share"), nil
}

func checkFileHandle(_ *os.File) error { return nil }

func safeEntry(info fs.FileInfo) bool { return info.Mode()&fs.ModeSymlink == 0 }

func ownedFile(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1 && info.Mode().IsRegular() && info.Mode().Perm()&0022 == 0
}

func syncDirectory(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}

func replaceFile(root *os.Root, from, to string) error {
	if err := root.Rename(from, to); err != nil {
		return err
	}
	return syncDirectory(root)
}
