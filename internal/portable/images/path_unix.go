//go:build !windows

package images

import (
	"io/fs"
	"os"
	"path/filepath"
)

func plainEntry(info fs.FileInfo) bool { return info.Mode()&fs.ModeSymlink == 0 }

func renameImageAt(root *os.Root, from, to string, rename func(int, string, int, string) error) error {
	src, err := root.Open(filepath.Dir(from))
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := root.Open(filepath.Dir(to))
	if err != nil {
		return err
	}
	defer dst.Close()
	return rename(int(src.Fd()), filepath.Base(from), int(dst.Fd()), filepath.Base(to))
}
