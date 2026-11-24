package sandbox

import "golang.org/x/sys/unix"

func renameNoReplace(srcDir int, src string, dstDir int, dst string) error {
	return unix.RenameatxNp(srcDir, src, dstDir, dst, unix.RENAME_EXCL)
}
