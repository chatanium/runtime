//go:build linux

package host

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"path/filepath"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	sharedhost "github.com/thirdscam/chatanium/internal/host"
	"golang.org/x/sys/unix"
)

func (s *Storage) nativeRoot(id, path string, project, uid, gid uint32) (NativeRootIdentity, error) {
	var result NativeRootIdentity
	f, err := openDirectory(path)
	if err != nil {
		return result, err
	}
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &st); err != nil {
		return result, err
	}
	if st.Dev != s.quota.device || st.Uid != uid || st.Gid != gid || st.Mode&07777 != 0700 {
		return result, errors.New("native root filesystem, owner or mode mismatch")
	}
	if err = s.quota.project(path, project, false); err != nil {
		return result, err
	}
	return NativeRootIdentity{RootID: id, HostPath: path, Dev: st.Dev, Ino: st.Ino, UID: st.Uid, GID: st.Gid, Mode: st.Mode & 07777, Project: project}, nil
}

func (s *Storage) PrepareRoots(ctx context.Context, l sharedhost.Lease) (gvxcontract.RootInitManifest, error) {
	if err := s.requireAdmission(); err != nil {
		return gvxcontract.RootInitManifest{}, err
	}
	var empty gvxcontract.RootInitManifest
	if err := s.Verify(ctx, l); err != nil {
		return empty, err
	}
	// The same instance may retry observation, but never issue a second intent.
	if existing, err := s.store.RootIntent(ctx, l.Ownership); err == nil {
		if _, err = s.observeRoots(l, existing.Native); err != nil {
			return empty, err
		}
		return existing.Manifest, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return empty, err
	}
	target := gvxcontract.RootAttrs{UID: l.Spec.UID, GID: l.Spec.GID, Mode: 0700}
	roots := make([]NativeRootIntent, 0, 3)
	for _, r := range []struct {
		id, path, mount string
		project         uint32
	}{
		{"persistent", l.PersistentPath, sharedhost.DataMountpoint, l.PersistentProject},
		{"scratch", l.ScratchPath, sharedhost.ScratchMountpoint, l.ScratchProject},
		{"tmp", filepath.Join(filepath.Dir(l.ScratchPath), "tmp"), "/tmp", l.ScratchProject},
	} {
		native, err := s.nativeRoot(r.id, r.path, r.project, l.SandboxUID, l.SandboxGID)
		if err != nil {
			return empty, err
		}
		guest := gvxcontract.RootInitEntry{RootID: r.id, Mountpoint: r.mount, Disposition: gvxcontract.RootDispositionNew, Pre: gvxcontract.RootAttrs{Mode: 0700}, Target: target}
		intent := l.Ownership.InstanceID + ":" + r.id
		if r.id == "persistent" {
			intent = l.Ownership.InstallationID + ":persistent"
			retained, ok, err := s.store.RetainedRoot(ctx, l.Ownership.InstallationID, r.id)
			if err != nil {
				return empty, err
			}
			if ok {
				if retained.Native != native || retained.Guest.Target != target {
					return empty, errors.New("retained guest root binding or approved attributes changed")
				}
				guest.Disposition = gvxcontract.RootDispositionRetained
				guest.Pre = target
			} else {
				pending, resume, err := s.store.PendingRoot(ctx, l.Ownership.InstallationID, r.id)
				if err != nil {
					return empty, err
				}
				if resume {
					if pending.Native != native || pending.Guest.Target != target {
						return empty, errors.New("pending root binding changed")
					}
					guest = pending.Guest
					intent = pending.StorageIntentID
				} else {
					// A native populated tree is not evidence of guest metadata semantics.
					// Interrupted intents are recovered by the store, never guessed here.
					f, err := openDirectory(r.path)
					if err != nil {
						return empty, err
					}
					entries, e := f.ReadDir(1)
					f.Close()
					if e != nil && !errors.Is(e, io.EOF) {
						return empty, e
					}
					if len(entries) != 0 {
						return empty, errors.New("unconfirmed populated persistent root requires its durable initialization intent")
					}
				}
			}
		}
		roots = append(roots, NativeRootIntent{Native: native, Guest: guest, StorageIntentID: intent})
	}
	return s.store.BeginRootIntent(ctx, l.Ownership, roots)
}

func (s *Storage) observeRoots(l sharedhost.Lease, roots []NativeRootIntent) ([]NativeRootIdentity, error) {
	observed := make([]NativeRootIdentity, 0, len(roots))
	for _, root := range roots {
		path, project := "", l.ScratchProject
		switch root.Native.RootID {
		case "persistent":
			path = l.PersistentPath
			project = l.PersistentProject
		case "scratch":
			path = l.ScratchPath
		case "tmp":
			path = filepath.Join(filepath.Dir(l.ScratchPath), "tmp")
		default:
			return nil, errors.New("unknown native root ID")
		}
		if root.Native.HostPath != path {
			return nil, errors.New("root intent contains unexpected native path")
		}
		got, err := s.nativeRoot(root.Native.RootID, path, project, l.SandboxUID, l.SandboxGID)
		if err != nil {
			return nil, err
		}
		if got != root.Native {
			return nil, errors.New("native root inode changed since intent")
		}
		observed = append(observed, got)
	}
	return observed, nil
}

func (s *Storage) ConfirmRoots(ctx context.Context, l sharedhost.Lease, result gvxcontract.RootInitResult) error {
	if err := s.requireAdmission(); err != nil {
		return err
	}
	if err := s.validateLease(l); err != nil {
		return err
	}
	if err := s.verifyBacking(); err != nil {
		return err
	}
	intent, err := s.store.RootIntent(ctx, l.Ownership)
	if err != nil {
		return err
	}
	observed, err := s.observeRoots(l, intent.Native)
	if err != nil {
		return err
	}
	return s.store.ConfirmRootIntent(ctx, l.Ownership, result, observed)
}
