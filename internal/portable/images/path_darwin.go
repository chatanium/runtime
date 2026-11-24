package images

import (
	"os"

	"golang.org/x/sys/unix"
)

func renameImageNoReplace(root *os.Root, from, to string) error {
	return renameImageAt(root, from, to, func(src int, srcName string, dst int, dstName string) error {
		return unix.RenameatxNp(src, srcName, dst, dstName, unix.RENAME_EXCL)
	})
}
