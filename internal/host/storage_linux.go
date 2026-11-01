//go:build linux

package host

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type storage struct {
	config  SupervisorConfig
	quota   *quotaFS
	journal *journal
}

func newStorage(c SupervisorConfig) (*storage, error) {
	q, err := newQuotaFS(c.StorageRoot, c.IPCRoot)
	if err != nil {
		return nil, err
	}
	s := &storage{config: c, quota: q}
	for _, p := range []string{filepath.Join(c.StorageRoot, "persistent"), filepath.Join(c.StorageRoot, "instances"), filepath.Join(c.ManagementDirectory, "logs")} {
		if err = mkdirTrusted(p, 0700); err != nil {
			q.root.Close()
			return nil, err
		}
	}
	return s, nil
}
func mkdirTrusted(path string, mode fs.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	f, err := trustedDirectory(path)
	if err != nil {
		return err
	}
	return f.Close()
}
func (s *storage) provision(ctx context.Context, l Lease) error {
	if err := s.quota.preflight(); err != nil {
		return err
	}
	// The durable claim already exists. Fresh project IDs must not already be
	// in use by unrelated directories on this managed filesystem.
	if err := s.quota.unused(l.ScratchProject); err != nil {
		return err
	}
	r := l.Spec.Resources
	err := s.provisionPersistent(ctx, l)
	if err != nil {
		return err
	}
	if err = s.quota.limit(l.ScratchProject, r.ScratchBytes, r.ScratchInodes); err != nil {
		return err
	}
	instanceRoot := filepath.Dir(l.ScratchPath)
	if err = os.Mkdir(instanceRoot, 0700); err != nil {
		return err
	}
	if err = os.Mkdir(l.ScratchPath, 0700); err != nil {
		return err
	}
	if err = s.quota.project(l.ScratchPath, l.ScratchProject, true); err != nil {
		return err
	}
	if err = os.Chown(l.ScratchPath, int(l.Spec.UID), int(l.Spec.GID)); err != nil {
		return err
	}
	if err = os.Mkdir(l.IPCPath, 0710); err != nil {
		return err
	}
	if err = s.quota.project(l.IPCPath, l.ScratchProject, true); err != nil {
		return err
	}
	if err = os.Chown(l.IPCPath, int(s.config.RuntimeUID), int(l.Spec.GID)); err != nil {
		return err
	}
	// Runtime owns the parent and can create go-plugin's per-client temp dir.
	// The module can traverse only its own bind mount, not host ancestors.
	if err = os.Chmod(l.IPCPath, 0710); err != nil {
		return err
	}
	if err = os.Mkdir(l.LogPath, 0700); err != nil {
		return err
	}
	return nil
}
func (s *storage) socketDirectory(l Lease, path string) error {
	rel, err := filepath.Rel(l.IPCPath, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return invalid("socket directory is not an instance IPC child")
	}
	// Resolve against a held root with openat2; no symlink or mount traversal.
	root, err := openDirectory(l.IPCPath)
	if err != nil {
		return err
	}
	defer root.Close()
	fd, err := unix.Openat2(int(root.Fd()), rel, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return err
	}
	// Only the runtime-created empty directory is handed to the module.
	f := os.NewFile(uintptr(fd), "socket-directory")
	defer f.Close()
	entries, err := f.ReadDir(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(entries) != 0 {
		return errors.New("bootstrap socket directory must be empty")
	}
	if err = s.quota.project(path, l.ScratchProject, false); err != nil {
		return err
	}
	if err = unix.Fchown(fd, int(l.Spec.UID), int(s.config.RuntimeGID)); err != nil {
		return err
	}
	return unix.Fchmod(fd, 0770)
}
func (s *storage) capture(l Lease, name string) (*os.File, error) {
	if name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, invalid("socket name must be canonical relative IPC path")
	}
	root, err := openDirectory(l.IPCPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	fd, err := unix.Openat2(int(root.Fd()), name, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "module-primary-socket")
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != l.Spec.UID || st.Gid != l.SocketGID || st.Mode&0777 != 0660 {
		f.Close()
		return nil, errors.New("primary socket has unauthorized type, owner, group or mode")
	}
	// O_PATH pins the inode across unlink/rename. The receiving process must
	// retain this descriptor until all go-plugin dial users have terminated.
	return f, nil
}
func (s *storage) cleanup(ctx context.Context, l Lease) error {
	var errs []error
	for _, resource := range []struct {
		path   string
		reason FailureReason
	}{{filepath.Dir(l.ScratchPath), FailureCleanupScratch}, {l.IPCPath, FailureCleanupIPC}, {l.LogPath, FailureCleanupLogs}} {
		if err := os.RemoveAll(resource.path); err != nil {
			errs = append(errs, cleanupStep(resource.reason, err))
		}
	}
	if err := s.quota.reclaimed(ctx, l.ScratchProject); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
func (s *storage) verify(l Lease) error {
	r := l.Spec.Resources
	return errors.Join(
		s.quota.verifyLimit(l.PersistentProject, r.PersistentBytes, r.PersistentInodes),
		s.quota.verifyLimit(l.ScratchProject, r.ScratchBytes, r.ScratchInodes),
		s.quota.project(l.PersistentPath, l.PersistentProject, false),
		s.quota.project(l.ScratchPath, l.ScratchProject, false),
		s.quota.project(l.IPCPath, l.ScratchProject, false),
	)
}

// Retained data may contain nested directories. Validate every inheritance
// boundary before remounting it; never rewrite module data to fix a mismatch.
// Read one directory entry at a time instead of sorting an unbounded directory.
func (s *storage) verifyDirectories(path string, project uint32) error {
	if err := s.quota.project(path, project, false); err != nil {
		return err
	}
	dir, err := openDirectory(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	for {
		entries, e := dir.ReadDir(1)
		for _, entry := range entries {
			if entry.IsDir() {
				if err = s.verifyDirectories(filepath.Join(path, entry.Name()), project); err != nil {
					return err
				}
			}
		}
		if errors.Is(e, io.EOF) {
			return nil
		}
		if e != nil {
			return e
		}
	}
}
func prepareRuntimeDirectory(parent *os.File, name string, uid, gid uint32) error {
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	fd, err := unix.Openat2(int(parent.Fd()), name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Uid != 0 && stat.Uid != uid {
		return errors.New("private runtime directory has foreign ownership")
	}
	if err = unix.Fchown(fd, int(uid), int(gid)); err != nil {
		return err
	}
	return unix.Fchmod(fd, 0700)
}
