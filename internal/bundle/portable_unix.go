//go:build linux || darwin

package bundle

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

func validPortableNode(info fs.FileInfo, expected fs.FileMode) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid() && info.Mode()&^(fs.ModeDir) == expected
}

func validPortableFileHandle(_ *os.File, info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

func syncPortableDirectory(root *os.Root, name string) error {
	f, err := root.Open(name)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
