//go:build linux

package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func (s *storage) provisionPersistent(ctx context.Context, l Lease) error {
	if s.journal == nil {
		return errors.New("persistent provisioning requires durable installation ownership")
	}
	phase, err := s.journal.persistentProvision(ctx, l)
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
		if e := s.journal.persistentTransition(ctx, l, phase.State, next, r.PersistentBytes, r.PersistentInodes); e != nil {
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
		return s.journal.claim(ctx, l.Spec.InstanceID, "persistent", "PERSISTENT_READY")
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
	if err = os.Chown(l.PersistentPath, int(l.Spec.UID), int(l.Spec.GID)); err != nil {
		return err
	}
	if err = s.verifyPersistentIdentity(l); err != nil {
		return err
	}
	if err = transition("READY"); err != nil {
		return err
	}
	return s.journal.claim(ctx, l.Spec.InstanceID, "persistent", "PERSISTENT_READY")
}

func (s *storage) verifyPersistentIdentity(l Lease) error {
	if err := s.verifyDirectories(l.PersistentPath, l.PersistentProject); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Lstat(l.PersistentPath, &st); err != nil {
		return err
	}
	if st.Uid != l.Spec.UID || st.Gid != l.Spec.GID {
		return errors.New("persistent ownership differs from installation")
	}
	return nil
}

func (s *storage) verifyPartialPersistentDirectory(l Lease) error {
	f, err := openDirectory(l.PersistentPath)
	if err != nil {
		return err
	}
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if st.Dev != s.quota.device || (st.Uid != 0 && st.Uid != l.Spec.UID) || (st.Gid != 0 && st.Gid != l.Spec.GID) {
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
