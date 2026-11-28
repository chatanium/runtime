//go:build linux

package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	sharedhost "github.com/thirdscam/chatanium/internal/host"

	"golang.org/x/sys/unix"
)

func (s *Storage) provisionPersistent(ctx context.Context, l sharedhost.Lease) error {
	if s.store == nil {
		return errors.New("persistent provisioning requires durable installation ownership")
	}
	phase, err := s.store.persistentProvision(ctx, l)
	if err != nil {
		return err
	}
	_, err = os.Lstat(l.PersistentPath)
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		return err
	}
	r := l.Spec.Resources
	// Validate geometry alignment before changing the checkpoint or any quota.
	if _, err = s.quota.projectLimits(l.PersistentProject, r.PersistentBytes, r.PersistentInodes); err != nil {
		return err
	}
	transition := func(next string) error {
		if e := s.store.persistentTransition(ctx, l, phase.State, next, r.PersistentBytes, r.PersistentInodes); e != nil {
			return e
		}
		phase = persistentProvision{State: next, Bytes: r.PersistentBytes, Inodes: r.PersistentInodes}
		return nil
	}
	switch phase.State {
	case "READY":
		if missing {
			return errors.New("completed persistent directory is missing; retained installation ownership cannot be recreated")
		}
		if err = s.verifyPersistentIdentity(l); err != nil {
			return err
		}
		if err = s.quota.limit(l.PersistentProject, r.PersistentBytes, r.PersistentInodes); err != nil {
			return err
		}
		if err = transition("READY"); err != nil {
			return err
		}
		return s.store.claim(ctx, l.Spec.InstanceID, "persistent", "PERSISTENT_READY")
	case "COLLISION":
		return errors.New("persistent project reservation encountered foreign allocation")
	case "RESERVED":
		if !missing {
			return errors.New("uninitialized persistent path is already occupied")
		}
		if err = s.quota.unused(l.PersistentProject); err != nil {
			return errors.Join(err, transition("COLLISION"))
		}
		// Persist proof that the project was unused before the first quota set.
		if err = transition("QUOTA_INTENT"); err != nil {
			return err
		}
	case "QUOTA_INTENT", "QUOTA_READY":
		if !missing {
			return errors.New("persistent path exists without a directory creation intent")
		}
		if err = s.quota.emptyUsage(l.PersistentProject); err != nil {
			return err
		}
	case "DIRECTORY_INTENT":
		if missing {
			if err = s.quota.emptyUsage(l.PersistentProject); err != nil {
				return err
			}
		} else if err = s.verifyPartialPersistentDirectory(l); err != nil {
			return err
		}
	default:
		return errors.New("unknown persistent provisioning phase")
	}
	// QUOTA_INTENT was written only after proving the reserved project unused.
	// Interrupted local quota settings may be reapplied within that durable
	// ownership; old installations without a checkpoint fail closed instead.
	if err = s.quota.limit(l.PersistentProject, r.PersistentBytes, r.PersistentInodes); err != nil {
		return err
	}
	if phase.State != "DIRECTORY_INTENT" {
		if err = transition("QUOTA_READY"); err != nil {
			return err
		}
		if err = transition("DIRECTORY_INTENT"); err != nil {
			return err
		}
	}
	if missing {
		if err = os.Mkdir(l.PersistentPath, 0700); err != nil {
			return err
		}
	}
	if err = s.quota.project(l.PersistentPath, l.PersistentProject, true); err != nil {
		return err
	}
	if err = os.Chown(l.PersistentPath, int(l.SandboxUID), int(l.SandboxGID)); err != nil {
		return err
	}
	if err = s.verifyPersistentIdentity(l); err != nil {
		return err
	}
	if err = transition("READY"); err != nil {
		return err
	}
	return s.store.claim(ctx, l.Spec.InstanceID, "persistent", "PERSISTENT_READY")
}

func (s *Storage) verifyPersistentIdentity(l sharedhost.Lease) error {
	if err := s.verifyDirectories(l.PersistentPath, l.PersistentProject); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Lstat(l.PersistentPath, &st); err != nil {
		return err
	}
	if st.Uid != l.SandboxUID || st.Gid != l.SandboxGID || st.Mode&0777 != 0700 {
		return errors.New("persistent native ownership or mode differs from installation")
	}
	return nil
}

func (s *Storage) verifyPartialPersistentDirectory(l sharedhost.Lease) error {
	f, err := openDirectory(l.PersistentPath)
	if err != nil {
		return err
	}
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if st.Dev != s.quota.device || (st.Uid != 0 && st.Uid != l.SandboxUID) || (st.Gid != 0 && st.Gid != l.SandboxGID) {
		return errors.New("partial persistent directory has foreign ownership")
	}
	entries, err := f.ReadDir(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(entries) != 0 {
		return errors.New("partial persistent directory contains unproven data")
	}
	var x fsxattr
	if err = ioctlXattr(f, 0x801c581f, &x); err != nil {
		return err
	}
	if x.ProjectID != 0 && x.ProjectID != l.PersistentProject {
		return errors.New("partial persistent directory belongs to another project")
	}
	if x.ProjectID == 0 && st.Uid != 0 {
		return errors.New("unassigned partial persistent directory is not supervisor owned")
	}
	return nil
}

func (q *quotaFS) emptyUsage(id uint32) error {
	d, err := q.get(id)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if d.Blocks != 0 || d.Inodes != 0 || d.RTBlocks != 0 {
		return fmt.Errorf("incomplete persistent project %d has unproven allocation", id)
	}
	return nil
}

// ValidateAppAllowance checks an explicitly approved subreservation of Data.
// The caller supplies aggregate upload/log/native requirements from its config.
func ValidateAppAllowance(b StorageBudget, requiredBytes, requiredInodes int64) error {
	if requiredBytes < 0 || requiredInodes < 0 {
		return invalid("negative native app storage requirement")
	}
	if requiredInodes < 4 {
		requiredInodes = 4
	} // app plus native/logs/uploads roots
	if b.AppBytes <= 0 || b.AppInodes <= 0 || b.AppBytes > b.DataBytes || b.AppInodes > b.DataInodes || requiredBytes > b.AppBytes || requiredInodes > b.AppInodes {
		return invalid("explicit app allowance does not cover native state, uploads and logs inside Data")
	}
	return nil
}

// PrepareApp is called before any worker can see the writable canonical tree.
// Its claim is retained across stop/uninstall and retired only with the volume.
func (s *Storage) PrepareApp(ctx context.Context) error {
	if err := s.requireAdmission(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateAppAllowance(s.installation.Budget, 0, 0); err != nil {
		return err
	}
	app := s.installation.Identities.App
	if app.UID == 0 || app.GID == 0 || s.config.RuntimeUID != app.UID || s.config.RuntimeGID != app.GID {
		return errors.New("native app identity differs from installed worker")
	}
	if s.installation.Budget.AppBytes%s.quota.blockBytes != 0 {
		return invalid("native app byte limit is not exactly representable by XFS")
	}
	project, err := s.store.ReserveAppStorage(ctx)
	if err != nil {
		return err
	}
	root := filepath.Join(s.config.StorageRoot, "app")
	if err = s.prepareAppDirectory(ctx, root, project, true); err != nil {
		return err
	}
	for _, name := range []string{"native", "logs", "uploads"} {
		if err = s.prepareAppDirectory(ctx, filepath.Join(root, name), project, false); err != nil {
			return err
		}
	}
	return s.VerifyApp(ctx)
}

func (s *Storage) appDirectoryRecord(ctx context.Context, path string) (ProvisionRecord, bool, error) {
	records, err := s.store.ObjectProvisions(ctx, "directory", path)
	if err != nil {
		return ProvisionRecord{}, false, err
	}
	var selected ProvisionRecord
	found := false
	for _, record := range records {
		if !record.ProductCreated || record.ExistedBefore {
			continue
		}
		var desired ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); err != nil {
			return ProvisionRecord{}, false, err
		}
		if desired.Path != path || desired.UID != s.installation.Identities.App.UID || desired.GID != s.installation.Identities.App.GID || desired.Mode != 0700 {
			continue
		}
		if !found || record.State == "OBSERVED" {
			selected = record
			found = true
		}
	}
	return selected, found, nil
}

func (s *Storage) observeAppDirectory(ctx context.Context, id, path string, f *os.File) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	return observeStorage(ctx, s.store, id, path, ProvisionProperties{Path: path, Dev: st.Dev, Ino: st.Ino, UID: st.Uid, GID: st.Gid, Mode: st.Mode & 07777, ProductCreated: true})
}

func (s *Storage) prepareAppDirectory(ctx context.Context, path string, project uint32, root bool) error {
	record, found, err := s.appDirectoryRecord(ctx, path)
	if err != nil {
		return err
	}
	var st unix.Stat_t
	err = unix.Lstat(path, &st)
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		return err
	}
	app := s.installation.Identities.App
	if missing {
		if s.installation.State != "PROVISIONING" || found && record.State == "OBSERVED" {
			return errors.New("known native app directory is missing; retained state cannot be recreated")
		}
		if root {
			if !found {
				if err = s.quota.unused(project); err != nil {
					return err
				}
			} else if err = s.quota.emptyUsage(project); err != nil {
				return err
			}
		}
		if !found {
			id, err := provisionObject(ctx, s.store, "directory", path, ProvisionProperties{Path: path, UID: app.UID, GID: app.GID, Mode: 0700, ProductCreated: true})
			if err != nil {
				return err
			}
			record.ID = id
		}
		// For the app root, this intent is durable proof that unused(project)
		// succeeded before the first quota mutation, just like retained roots.
		if root {
			if err = s.quota.limit(project, s.installation.Budget.AppBytes, s.installation.Budget.AppInodes); err != nil {
				return err
			}
		}
		if err = os.Mkdir(path, 0700); err != nil {
			return err
		}
		f, err := openDirectory(path)
		if err != nil {
			return err
		}
		err = f.Sync()
		if err == nil {
			parent, e := openDirectory(filepath.Dir(path))
			if e != nil {
				err = e
			} else {
				err = parent.Sync()
				parent.Close()
			}
		}
		if err == nil {
			err = s.observeAppDirectory(ctx, record.ID, path, f)
		}
		f.Close()
		if err != nil {
			return err
		}
		record, found, err = s.appDirectoryRecord(ctx, path)
		if err != nil {
			return err
		}
	}
	if !found || record.State != "OBSERVED" {
		return errors.New("native app inode has no durable observed identity")
	}
	var observed ProvisionProperties
	if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &observed); err != nil {
		return err
	}
	f, err := openDirectory(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if st.Dev != s.quota.device || st.Dev != observed.Dev || st.Ino != observed.Ino {
		return errors.New("native app inode differs from installation ledger")
	}
	if root {
		if err = s.quota.verifyLimit(project, s.installation.Budget.AppBytes, s.installation.Budget.AppInodes); err != nil {
			return err
		}
	}
	if observed.UID == app.UID && observed.GID == app.GID && observed.Mode == 0700 {
		if st.Uid != app.UID || st.Gid != app.GID || st.Mode&07777 != 0700 {
			return errors.New("retained native app ownership or mode changed")
		}
		return s.quota.project(path, project, false)
	}
	if s.installation.State != "PROVISIONING" || observed.UID != 0 || observed.GID != 0 || observed.Mode != 0700 || st.Mode&07777 != 0700 || st.Uid != 0 && st.Uid != app.UID || st.Gid != 0 && st.Gid != app.GID {
		return errors.New("native app initialization has unknown attributes")
	}
	entries, err := f.ReadDir(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(entries) != 0 {
		return errors.New("incomplete native app directory contains unproven data")
	}
	if err = s.quota.project(path, project, true); err != nil {
		return err
	}
	if err = unix.Fchown(int(f.Fd()), int(app.UID), int(app.GID)); err != nil {
		return err
	}
	if err = unix.Fchmod(int(f.Fd()), 0700); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return s.observeAppDirectory(ctx, record.ID, path, f)
}

func (s *Storage) VerifyApp(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	project, err := s.store.AppStorageProject(ctx)
	if err != nil {
		return err
	}
	if err = s.quota.verifyLimit(project, s.installation.Budget.AppBytes, s.installation.Budget.AppInodes); err != nil {
		return err
	}
	app := s.installation.Identities.App
	root := filepath.Join(s.config.StorageRoot, "app")
	for _, path := range []string{root, filepath.Join(root, "native"), filepath.Join(root, "logs"), filepath.Join(root, "uploads")} {
		record, found, err := s.appDirectoryRecord(ctx, path)
		if err != nil {
			return err
		}
		if !found || record.State != "OBSERVED" {
			return errors.New("native app root lacks observed initialization")
		}
		var observed ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &observed); err != nil {
			return err
		}
		id, err := s.nativeRoot("app", path, project, app.UID, app.GID)
		if err != nil {
			return err
		}
		if id.Dev != observed.Dev || id.Ino != observed.Ino || observed.UID != app.UID || observed.GID != app.GID || observed.Mode != 0700 {
			return errors.New("native app root differs from completed initialization")
		}
	}
	return s.verifyDirectories(root, project)
}
