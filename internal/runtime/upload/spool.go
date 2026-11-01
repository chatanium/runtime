// Package upload implements the backend-neutral, instance-owned core file store.
package upload

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// spool holds both the directory inode and an exclusive process lock. The lock
// file is never unlinked: replacing it would permit two independent owners.
type spool struct {
	directory *os.File
	lock      *os.File
}

func openSpool(ctx context.Context, management string) (_ *spool, result error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(management) || filepath.Clean(management) != management {
		return nil, invalid()
	}
	fd, err := unix.Open(management, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, internal()
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	// The supervisor may own this parent and grant only runtime-group
	// traversal; journal files remain private. Never chmod a shared ancestor.
	if unix.Fstat(fd, &stat) != nil || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || stat.Mode&0027 != 0 {
		return nil, invalid()
	}
	root, err := unix.Openat(fd, "uploads", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, internal()
	}
	s := &spool{directory: os.NewFile(uintptr(root), "uploads")}
	defer func() {
		if result != nil {
			s.close()
		}
	}()
	if unix.Fstat(root, &stat) != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0777 != 0700 {
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
	if unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, internal()
	}
	// No refs survive a runtime epoch. Only our exact internal file namespace is
	// reclaimed, and only after acquiring exclusive ownership of this directory.
	for {
		entries, readErr := s.directory.ReadDir(1)
		if len(entries) == 0 {
			if readErr != nil && readErr != io.EOF {
				return nil, internal()
			}
			break
		}
		if ctx.Err() != nil {
			return nil, contextFailure(ctx)
		}
		name := entries[0].Name()
		if name == ".owner" {
			continue
		}
		if !spoolName(name) {
			return nil, invalid()
		}
		if unix.Fstatat(root, name, &stat, unix.AT_SYMLINK_NOFOLLOW) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
			return nil, invalid()
		}
		if unix.Unlinkat(root, name, 0) != nil {
			return nil, internal()
		}
	}
	return s, nil
}

func spoolName(name string) bool {
	if !strings.HasPrefix(name, "file-") || len(name) != len("file-")+32 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(name, "file-"))
	return err == nil
}

func newID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", internal()
	}
	return hex.EncodeToString(bytes[:]), nil
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
	return os.NewFile(uintptr(fd), "upload reader"), nil
}

func (s *spool) remove(name string) error {
	if err := unix.Unlinkat(int(s.directory.Fd()), name, 0); err != nil && err != unix.ENOENT {
		return internal()
	}
	return nil
}

func (s *spool) close() error {
	var result error
	if s.lock != nil {
		if err := s.lock.Close(); err != nil {
			result = internal()
		}
	}
	if s.directory != nil {
		if err := s.directory.Close(); err != nil {
			result = internal()
		}
	}
	return result
}
