//go:build linux

package host

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Storage owns native XFS identities. Guest virtual identities are exclusively
// initialized by the authenticated bridge; they are never native chown inputs.
type Storage struct {
	config       SupervisorConfig
	quota        *quotaFS
	store        *Store
	systemd      *Systemd
	installation InstallationManifest
	cleanupOnly  bool
}

func NewStorage(ctx context.Context, c SupervisorConfig, store *Store, systemd *Systemd) (*Storage, error) {
	return openStorage(ctx, c, store, systemd, false)
}

// OpenStorageForCleanup never provisions paths or grants new launch authority.
func OpenStorageForCleanup(ctx context.Context, c SupervisorConfig, store *Store, systemd *Systemd) (*Storage, error) {
	return openStorage(ctx, c, store, systemd, true)
}

func openStorage(ctx context.Context, c SupervisorConfig, store *Store, systemd *Systemd, cleanupOnly bool) (*Storage, error) {
	if store == nil || systemd == nil {
		return nil, errors.New("storage requires the live installation store and systemd owner")
	}
	if err := store.requireLease(); err != nil {
		return nil, err
	}
	m, err := store.Installation(ctx)
	if err != nil {
		return nil, err
	}
	if m.RuntimeInstallationID != c.RuntimeInstallationID || m.Paths.StorageRoot != c.StorageRoot || c.ManagementDirectory != m.Paths.Control || m.Identities.Sandbox != c.Sandbox || c.Sandbox.UID == 0 || c.Sandbox.GID == 0 {
		return nil, errors.New("storage installation or native sandbox identity mismatch")
	}
	if err := validateBackingBudget(m); err != nil {
		return nil, err
	}
	q, err := newQuotaFS(c.StorageRoot, c.StorageRoot)
	if err != nil {
		return nil, err
	}
	s := &Storage{config: c, quota: q, store: store, systemd: systemd, installation: m, cleanupOnly: cleanupOnly}
	if err = s.verifyBacking(); err != nil {
		q.root.Close()
		return nil, err
	}
	if !cleanupOnly {
		if err = s.prepareWorkerTraversal(ctx); err != nil {
			q.root.Close()
			return nil, err
		}
		if err = s.PrepareApp(ctx); err != nil {
			q.root.Close()
			return nil, err
		}
	}
	return s, nil
}

// Close releases the mount pin only after all admission/storage users have
// joined. The manager must close it before detaching the installation backing.
func (s *Storage) Close() error {
	if s == nil || s.quota == nil || s.quota.root == nil {
		return nil
	}
	err := s.quota.root.Close()
	if errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
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

func (s *Storage) validateLease(l Lease) error {
	base := filepath.Join(s.config.StorageRoot, "instances", l.Spec.InstanceID)
	if !safeID(l.Spec.InstanceID) || !safeID(l.Ownership.InstallationID) ||
		l.Ownership.RuntimeInstallationID != s.installation.RuntimeInstallationID ||
		l.Spec.InstanceID != l.Ownership.InstanceID || l.SandboxUID != s.config.Sandbox.UID ||
		l.SandboxGID != s.config.Sandbox.GID || l.Spec.UID == 0 || l.Spec.GID == 0 ||
		l.PersistentPath != filepath.Join(s.config.StorageRoot, "persistent", l.Ownership.InstallationID) ||
		l.ScratchPath != filepath.Join(base, "scratch") || l.IPCPath != filepath.Join(base, "ipc") ||
		l.LogPath != filepath.Join(base, "logs") || l.BootstrapPath != filepath.Join(base, "bootstrap") || l.PersistentProject == 0 ||
		l.ScratchProject == 0 || l.PersistentProject == l.ScratchProject {
		return errors.New("storage lease paths or native identities are not controller-owned")
	}
	return s.store.requireLease()
}

func (s *Storage) Prepare(ctx context.Context, l Lease) error {
	if err := s.requireAdmission(); err != nil {
		return err
	}
	if err := s.validateLease(l); err != nil {
		return err
	}
	if err := s.verifyBacking(); err != nil {
		return err
	}
	if err := s.quota.preflight(); err != nil {
		return err
	}
	if err := s.quota.unused(l.ScratchProject); err != nil {
		return err
	}
	if err := s.provisionPersistent(ctx, l); err != nil {
		return err
	}
	r := l.Spec.Resources
	if err := s.quota.limit(l.ScratchProject, r.ScratchBytes, r.ScratchInodes); err != nil {
		return err
	}
	root := filepath.Dir(l.ScratchPath)
	intent, err := provisionObject(ctx, s.store, "directory", root, ProvisionProperties{Path: root, UID: 0, GID: s.config.RuntimeGID, Mode: 0710, ProductCreated: true})
	if err != nil {
		return err
	}
	if err = os.Mkdir(root, 0710); err != nil {
		return err
	}
	rootFD, err := openDirectory(root)
	if err != nil {
		return err
	}
	err = unix.Fchown(int(rootFD.Fd()), 0, int(s.config.RuntimeGID))
	if err == nil {
		err = unix.Fchmod(int(rootFD.Fd()), 0710)
	}
	err = errors.Join(err, rootFD.Close())
	if err != nil {
		return err
	}
	var st unix.Stat_t
	if err = unix.Lstat(root, &st); err != nil {
		return err
	}
	if err = observeStorage(ctx, s.store, intent, root, ProvisionProperties{Path: root, Dev: st.Dev, Ino: st.Ino, GID: s.config.RuntimeGID, Mode: 0710, ProductCreated: true}); err != nil {
		return err
	}
	if err = s.quota.project(root, l.ScratchProject, true); err != nil {
		return err
	}
	for _, child := range []struct {
		path     string
		uid, gid uint32
		mode     uint32
	}{
		{l.ScratchPath, l.SandboxUID, l.SandboxGID, 0700},
		{filepath.Join(root, "tmp"), l.SandboxUID, l.SandboxGID, 0700},
		{filepath.Join(root, "work"), l.SandboxUID, l.SandboxGID, 0700},
		{l.IPCPath, 0, s.config.RuntimeGID, 0710},
		{l.LogPath, 0, 0, 0700},
		{l.BootstrapPath, s.config.RuntimeUID, s.config.RuntimeGID, 0700},
	} {
		if err := os.Mkdir(child.path, fs.FileMode(child.mode)); err != nil {
			return err
		}
		if err := s.quota.project(child.path, l.ScratchProject, false); err != nil {
			return err
		}
		f, err := openDirectory(child.path)
		if err != nil {
			return err
		}
		err = unix.Fchown(int(f.Fd()), int(child.uid), int(child.gid))
		if err == nil {
			err = unix.Fchmod(int(f.Fd()), child.mode)
		}
		err = errors.Join(err, f.Close())
		if err != nil {
			return err
		}
	}
	return s.Verify(ctx, l)
}

func (s *Storage) Cleanup(ctx context.Context, l Lease) error {
	if err := s.validateLease(l); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrCleanupIncomplete, err)
	}
	evidence, err := s.systemd.StorageCleanupBarrier(ctx, l.Ownership)
	if err != nil {
		return err
	}
	if err = validateStorageWriters(evidence); err != nil {
		return err
	}
	if err := s.verifyBacking(); err != nil {
		return err
	}
	root := filepath.Dir(l.ScratchPath)
	// No lazy unmount and no forced deletion: an owned mount or retained writer
	// must keep the durable claim, even if all pathnames could be unlinked.
	if err := requireNoMounts(root); err != nil {
		return err
	}
	if _, err := os.Lstat(root); err == nil {
		if err = s.verifyCleanupRoot(ctx, root, l.ScratchProject); err != nil {
			return err
		}
		if err = os.RemoveAll(root); err != nil {
			return cleanupStep(FailureCleanupScratch, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := s.quota.reclaimed(ctx, l.ScratchProject); err != nil {
		return err
	}
	evidence.MountsAbsent = true
	evidence.QuotaReclaimed = true
	return s.completeStorageDirectory(ctx, root, evidence)
}

func (s *Storage) Verify(ctx context.Context, l Lease) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.validateLease(l); err != nil {
		return err
	}
	if err := s.verifyBacking(); err != nil {
		return err
	}
	r := l.Spec.Resources
	if _, err := s.nativeRoot("bootstrap", l.BootstrapPath, l.ScratchProject, s.config.RuntimeUID, s.config.RuntimeGID); err != nil {
		return err
	}
	return errors.Join(
		s.quota.verifyLimit(l.PersistentProject, r.PersistentBytes, r.PersistentInodes),
		s.quota.verifyLimit(l.ScratchProject, r.ScratchBytes, r.ScratchInodes),
		s.verifyPersistentIdentity(l),
		s.quota.project(filepath.Dir(l.ScratchPath), l.ScratchProject, false),
		s.quota.project(l.ScratchPath, l.ScratchProject, false),
		s.quota.project(filepath.Join(filepath.Dir(l.ScratchPath), "tmp"), l.ScratchProject, false),
		s.quota.project(filepath.Join(filepath.Dir(l.ScratchPath), "work"), l.ScratchProject, false),
		s.quota.project(l.IPCPath, l.ScratchProject, false),
		s.quota.project(l.LogPath, l.ScratchProject, false),
		s.quota.project(l.BootstrapPath, l.ScratchProject, false),
	)
}

// Retained data may contain nested directories. Validate every inheritance
// boundary before remounting it; never rewrite module data to fix a mismatch.
// Read one directory entry at a time instead of sorting an unbounded directory.
func (s *Storage) verifyDirectories(path string, project uint32) error {
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

func (s *Storage) requireAdmission() error {
	if s.cleanupOnly {
		return errors.New("cleanup-only storage cannot admit or initialize workload resources")
	}
	return nil
}
