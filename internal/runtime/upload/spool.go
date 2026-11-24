//go:build linux || (darwin && arm64)

package upload

import (
	"context"
	"os"
	"path/filepath"

	"github.com/thirdscam/chatanium/internal/portable/process"
	"golang.org/x/sys/unix"
)

func openSpool(ctx context.Context, management string, portable bool) (_ *spool, result error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(management) || filepath.Clean(management) != management {
		return nil, invalid()
	}
	search := managementSearchFlag
	if portable {
		if err := process.CheckPrivateDir(management); err != nil {
			return nil, invalid()
		}
		search = unix.O_RDONLY
	}
	fd, err := unix.Open(management, search|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, internal()
	}
	var stat unix.Stat_t
	if portable {
		parent := os.NewFile(uintptr(fd), "upload management")
		defer parent.Close()
		if unix.Fstat(fd, &stat) != nil || stat.Mode&07777 != 0700 || process.CheckPrivateFileACL(parent) != nil {
			return nil, invalid()
		}
	} else {
		defer unix.Close(fd)
		// The legacy supervisor may own this parent and grant only runtime-group
		// traversal; journal files remain private. Never chmod a shared ancestor.
		if unix.Fstat(fd, &stat) != nil || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || stat.Mode&0027 != 0 {
			return nil, invalid()
		}
	}
	root, err := unix.Openat(fd, "uploads", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, internal()
	}
	s := &spool{directory: os.NewFile(uintptr(root), "uploads"), portable: portable}
	defer func() {
		if result != nil {
			s.close()
		}
	}()
	if unix.Fstat(root, &stat) != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0777 != 0700 || portable && stat.Mode&07777 != 0700 {
		return nil, invalid()
	}
	if portable && process.CheckPrivateFileACL(s.directory) != nil {
		return nil, invalid()
	}
	lock, err := unix.Openat(root, ".owner", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, internal()
	}
	s.lock = os.NewFile(uintptr(lock), "upload ownership")
	if unix.Fstat(lock, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Mode&077 != 0 {
		return nil, invalid()
	}
	if portable && process.CheckPrivateFileACL(s.lock) != nil {
		return nil, invalid()
	}
	if unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, internal()
	}
	if err := s.recover(ctx, portable); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *spool) removeOrphan(name string) error {
	fd := int(s.directory.Fd())
	var stat unix.Stat_t
	if unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return invalid()
	}
	if s.portable {
		file, err := s.open(name)
		if err != nil {
			return err
		}
		if err := file.Close(); err != nil {
			return internal()
		}
	}
	if unix.Unlinkat(fd, name, 0) != nil {
		return internal()
	}
	return nil
}

func (s *spool) create(name string) (*os.File, error) {
	fd, err := unix.Openat(int(s.directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, internal()
	}
	return os.NewFile(uintptr(fd), "upload writer"), nil
}

func (s *spool) open(name string) (*os.File, error) {
	fd, err := unix.Openat(int(s.directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, internal()
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) {
		unix.Close(fd)
		return nil, internal()
	}
	file := os.NewFile(uintptr(fd), "upload reader")
	if s.portable && process.CheckPrivateFileACL(file) != nil {
		file.Close()
		return nil, internal()
	}
	return file, nil
}

func (s *spool) remove(name string) error {
	if err := unix.Unlinkat(int(s.directory.Fd()), name, 0); err != nil && err != unix.ENOENT {
		return internal()
	}
	return nil
}
