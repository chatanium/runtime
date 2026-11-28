//go:build linux

package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/legacy/host"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
)

func currentBootID() (string, error) {
	raw, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return "", e
	}
	boot := strings.TrimSpace(string(raw))
	if boot == "" {
		return "", errors.New("kernel boot identity unavailable")
	}
	return boot, nil
}
func bootDirectoryPath(m host.InstallationManifest, path string) bool {
	return path == m.Paths.RunRoot || path == filepath.Join(m.Paths.RunRoot, "netns") || path == filepath.Join(m.Paths.RunRoot, "instances")
}
func bootDirectoryProperties(m host.InstallationManifest, path string) host.ProvisionProperties {
	mode, gid := uint32(0710), m.Identities.App.GID
	if path == filepath.Join(m.Paths.RunRoot, "netns") {
		mode, gid = 0700, 0
	}
	return host.ProvisionProperties{Path: path, Parent: filepath.Dir(path), Mode: mode, GID: gid, ProductCreated: true}
}
func recordBootDirectory(ctx context.Context, store *host.Store, m host.InstallationManifest, path, recordID string) error {
	if !bootDirectoryPath(m, path) {
		return nil
	}
	var fs unix.Statfs_t
	if e := unix.Statfs(path, &fs); e != nil {
		return e
	}
	if fs.Type != unix.TMPFS_MAGIC {
		return nil
	}
	record, e := store.Provision(ctx, recordID)
	if e != nil {
		return e
	}
	if e = matchRecord(record); e != nil {
		return e
	}
	var p host.ProvisionProperties
	if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
		return e
	}
	boot, e := currentBootID()
	if e != nil {
		return e
	}
	return store.RecordBootEphemeral(ctx, host.BootEphemeralRecord{Path: path, BootID: boot, DirectoryRecordID: recordID, Dev: p.Dev, Ino: p.Ino, FilesystemType: fs.Type})
}
func oldBootDirectoryMissing(ctx context.Context, store *host.Store, m host.InstallationManifest, path string) (bool, error) {
	if !bootDirectoryPath(m, path) {
		return false, nil
	}
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		return false, e
	}
	marker, e := store.BootEphemeral(ctx, path)
	if errors.Is(e, sql.ErrNoRows) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	boot, e := currentBootID()
	if e != nil {
		return false, e
	}
	if marker.BootID == boot {
		return false, errors.New("same-boot run directory disappearance cannot authorize recreation")
	}
	record, e := store.Provision(ctx, marker.DirectoryRecordID)
	if e != nil {
		return false, e
	}
	if record.CleanupState == "COMPLETE" {
		return false, errors.New("removed run directory cannot be resurrected")
	}
	if _, removed, e := removalFor(ctx, store, record); e != nil {
		return false, e
	} else if removed {
		return false, errors.New("run directory has explicit removal authority, not recreation authority")
	}
	return true, nil
}
func ensureBootEphemeral(ctx context.Context, store *host.Store, m host.InstallationManifest, proof host.CleanupEvidence) error {
	boot, e := currentBootID()
	if e != nil {
		return e
	}
	if proof.BootID != boot {
		return errors.New("ephemeral cleanup evidence boot changed")
	}
	for _, path := range []string{m.Paths.RunRoot, filepath.Join(m.Paths.RunRoot, "netns"), filepath.Join(m.Paths.RunRoot, "instances")} {
		marker, markerErr := store.BootEphemeral(ctx, path)
		if markerErr != nil && !errors.Is(markerErr, sql.ErrNoRows) {
			return markerErr
		}
		_, statErr := os.Lstat(path)
		if markerErr != nil {
			if statErr != nil {
				return errors.Join(errors.New("missing run directory lacks recorded ephemeral boot authority"), statErr)
			}
			record, e := ownedRecord(ctx, store, "directory", path)
			if e != nil {
				return e
			}
			if e = matchRecord(record); e != nil {
				return e
			}
			var fs unix.Statfs_t
			if e = unix.Statfs(path, &fs); e != nil {
				return e
			}
			if fs.Type == unix.TMPFS_MAGIC {
				return errors.New("tmpfs run directory requires initialization boot binding")
			}
			continue
		}
		if marker.BootID == boot {
			record, e := store.Provision(ctx, marker.DirectoryRecordID)
			if e != nil {
				return e
			}
			if record.CleanupState == "COMPLETE" {
				return errors.New("retired run root cannot be reused")
			}
			if statErr != nil {
				return errors.Join(errors.New("same-boot run directory disappearance"), statErr)
			}
			if e = matchRecord(record); e != nil {
				return e
			}
			continue
		}
		previous, e := store.Provision(ctx, marker.DirectoryRecordID)
		if e != nil {
			return e
		}
		if previous.CleanupState == "COMPLETE" {
			return errors.New("removed ephemeral directory cannot be recreated")
		}
		if _, removed, e := removalFor(ctx, store, previous); e != nil {
			return e
		} else if removed {
			return errors.New("ephemeral path has an approved removal, not recreation")
		}
		sum, e := digest("chatanium-boot-directory-v1", struct{ Path, Boot string }{path, boot})
		if e != nil {
			return e
		}
		id := "bootdir-" + strings.TrimPrefix(sum, "sha256:")
		desired := bootDirectoryProperties(m, path)
		current, e := store.Provision(ctx, id)
		if e == nil && (current.Kind != "directory" || current.Identity != path || string(current.Desired) != string(provisionJSON(desired))) {
			return errors.New("boot directory intent identity changed")
		}
		if e == nil && current.State == "OBSERVED" {
			if current.CleanupState == "COMPLETE" {
				return errors.New("removed current-boot directory cannot be reused")
			}
			if e = matchRecord(current); e != nil {
				return e
			}
		} else {
			if statErr == nil {
				return errors.New("unobserved current-boot run directory cannot be adopted")
			}
			if !os.IsNotExist(statErr) {
				return statErr
			}
			if e != nil && !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			if e = trustedPath(filepath.Dir(path), false); e != nil {
				return e
			}
			var fs unix.Statfs_t
			if e = unix.Statfs(filepath.Dir(path), &fs); e != nil {
				return e
			}
			if fs.Type != unix.TMPFS_MAGIC {
				return errors.New("persistent run directory disappearance cannot authorize recreation")
			}
			if current.ID == "" {
				if e = store.BeginProvision(ctx, host.ProvisionIntent{ID: id, Kind: "directory", Identity: path, ProductCreated: true, Desired: provisionJSON(desired)}); e != nil {
					return e
				}
			}
			if e = os.Mkdir(path, os.FileMode(desired.Mode)); e != nil {
				return e
			}
			if e = os.Chown(path, 0, int(desired.GID)); e != nil {
				return e
			}
			if e = os.Chmod(path, os.FileMode(desired.Mode)); e != nil {
				return e
			}
			if e = syncDirectory(filepath.Dir(path)); e != nil {
				return e
			}
			if e = observePath(ctx, store, id, path, desired); e != nil {
				return e
			}
		}
		if e = recordBootDirectory(ctx, store, m, path, id); e != nil {
			return e
		}
		if proof.BootID != boot {
			return errors.New("ephemeral cleanup evidence boot changed")
		}
		if e = store.CompleteProvisionCleanup(ctx, previous.ID, proof); e != nil {
			return e
		}
	}
	return nil
}
func ensureWorkerSocketProjection(ctx context.Context, store *host.Store, m host.InstallationManifest, proof host.CleanupEvidence) error {
	boot, e := currentBootID()
	if e != nil {
		return e
	}
	if proof.BootID != boot {
		return errors.New("socket cleanup evidence boot changed")
	}
	path := filepath.Join(m.Paths.RunRoot, "worker-runtime.sock")
	records, e := store.ObjectProvisions(ctx, "config", path)
	if e != nil {
		return e
	}
	var prior *host.ProvisionRecord
	for index := range records {
		record := records[index]
		if record.State != "OBSERVED" {
			continue
		}
		var p host.ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
			return e
		}
		if _, removed, e := removalFor(ctx, store, record); e != nil {
			return e
		} else if removed {
			return errors.New("retired worker socket projection cannot be recreated")
		}
		if record.CleanupState == "COMPLETE" {
			continue
		}
		if p.Source == "boot-ephemeral:"+boot {
			if e = matchRecord(record); e != nil {
				return e
			}
			return validateWorkerPlaceholder(path)
		}
		if !strings.HasPrefix(p.Source, "boot-ephemeral:") {
			return errors.New("worker socket projection lacks boot authority")
		}
		if prior != nil {
			return errors.New("ambiguous previous worker socket projection")
		}
		copy := record
		prior = &copy
	}
	if _, e = os.Lstat(path); e == nil {
		return errors.New("unknown worker socket projection cannot be adopted")
	} else if !os.IsNotExist(e) {
		return e
	}
	if prior != nil {
		parent, e := store.BootEphemeral(ctx, m.Paths.RunRoot)
		if e != nil {
			return e
		}
		if parent.BootID != boot || parent.FilesystemType != unix.TMPFS_MAGIC {
			return errors.New("persistent socket target cannot be recreated")
		}
	}
	desired := host.ProvisionProperties{Path: path, Source: "boot-ephemeral:" + boot, Mode: 0600, ProductCreated: true}
	sum, e := digest("chatanium-boot-socket-v1", struct{ Path, Boot string }{path, boot})
	if e != nil {
		return e
	}
	id := "bootsocket-" + strings.TrimPrefix(sum, "sha256:")
	intent, e := store.Provision(ctx, id)
	if errors.Is(e, sql.ErrNoRows) {
		if e = store.BeginProvision(ctx, host.ProvisionIntent{ID: id, Kind: "config", Identity: path, ProductCreated: true, Desired: provisionJSON(desired)}); e != nil {
			return e
		}
	} else if e != nil {
		return e
	} else if intent.Kind != "config" || intent.Identity != path || intent.State != "INTENT" || intent.CleanupState == "COMPLETE" || string(intent.Desired) != string(provisionJSON(desired)) {
		return errors.New("socket projection intent changed")
	}
	file, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	e = errors.Join(file.Chmod(0600), file.Sync(), file.Close())
	if e != nil {
		return e
	}
	if e = syncDirectory(m.Paths.RunRoot); e != nil {
		return e
	}
	if e = observePath(ctx, store, id, path, desired); e != nil {
		return e
	}
	if prior != nil {
		return store.CompleteProvisionCleanup(ctx, prior.ID, proof)
	}
	return nil
}
func bootEphemeralAbsent(ctx context.Context, store *host.Store, record host.ProvisionRecord) (bool, error) {
	if record.State != "OBSERVED" || !record.ProductCreated || record.ExistedBefore {
		return false, nil
	}
	m, e := store.Installation(ctx)
	if e != nil {
		return false, e
	}
	var p host.ProvisionProperties
	if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
		return false, e
	}
	boot, e := currentBootID()
	if e != nil {
		return false, e
	}
	if record.Kind == "directory" && bootDirectoryPath(m, record.Identity) {
		marker, e := store.BootEphemeral(ctx, record.Identity)
		if errors.Is(e, sql.ErrNoRows) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		if marker.DirectoryRecordID != record.ID || marker.Dev != p.Dev || marker.Ino != p.Ino || marker.BootID == boot || marker.FilesystemType != unix.TMPFS_MAGIC {
			return false, nil
		}
	} else if record.Kind == "config" && record.Identity == filepath.Join(m.Paths.RunRoot, "worker-runtime.sock") && strings.HasPrefix(p.Source, "boot-ephemeral:") && p.Source != "boot-ephemeral:"+boot {
		marker, e := store.BootEphemeral(ctx, m.Paths.RunRoot)
		if e != nil {
			return false, e
		}
		if marker.FilesystemType != unix.TMPFS_MAGIC {
			return false, nil
		}
	} else {
		return false, nil
	}
	if _, e = os.Lstat(record.Identity); e == nil {
		return false, errors.New("old-boot ephemeral path reappeared without observed current ownership")
	} else if !os.IsNotExist(e) {
		return false, e
	}
	return true, trustedPathParent(record.Identity)
}
func validateWorkerPlaceholder(path string) error {
	var st unix.Stat_t
	if e := unix.Lstat(path, &st); e != nil {
		return e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != 0 || st.Nlink != 1 || st.Size != 0 {
		return errors.New("worker socket projection is not a protected empty regular placeholder")
	}
	return nil
}
