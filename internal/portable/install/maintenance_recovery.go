package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/thirdscam/chatanium/internal/portable/preparehost"
	"github.com/thirdscam/chatanium/internal/portable/sandbox"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

const (
	backupIntent    = "update.next"
	backupStage     = "next-code"
	backupPublishID = "next-code.id"
)

func ownedPreparation(p store.Preparation) bool {
	return generationPattern.MatchString(p.ID) && generationPattern.MatchString(p.EpochID) && p.Path == "preparations/"+p.ID
}

func ownedImage(img store.Image) bool {
	return generationPattern.MatchString(img.ID) && generationPattern.MatchString(img.EpochID) && img.Path == "images/"+img.EpochID+"/"+img.ID &&
		(img.PreparationID == "" || generationPattern.MatchString(img.PreparationID))
}

func ownedBackup(b store.Backup, m Manifest) bool {
	return generationPattern.MatchString(b.ID) && generationPattern.MatchString(b.EpochID) && b.Path == "backups/"+b.ID && b.Owner == m.Owner && b.InstallationIdentity.ID == m.ID &&
		b.Target == identity(m).Target && digestPattern.MatchString(b.BundleDigest) && digestPattern.MatchString(b.EngineDigest)
}

func ownedVolume(v store.Volume) bool {
	return generationPattern.MatchString(v.ID) && v.Path == "volumes/"+v.ID+".ext4"
}

func maintenanceDirectoryAt(root *os.Root, name string, create bool) (*os.Root, error) {
	parent, leaf, closeParent, err := maintenanceParent(root, name, create)
	if err != nil {
		return nil, err
	}
	defer closeParent()
	if create {
		// The generation itself must not already exist, even if the name is valid.
		if err := parent.Mkdir(leaf, 0700); err != nil {
			return nil, err
		}
		if err := syncDirectory(parent); err != nil {
			return nil, err
		}
	}
	return maintenanceDir(parent, leaf)
}

func maintenanceDirPresent(root *os.Root, name string) (bool, error) {
	d, err := maintenanceDirectoryAt(root, name, false)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, d.Close()
}

func removeMaintenanceDirectory(root *os.Root, path string) error {
	present, err := maintenanceDirPresent(root, path)
	if err != nil || !present {
		return err
	}
	return removeMaintenancePath(root, path)
}

// recoverAbandoned never treats PID absence, stale sockets, or an unlocked
// owner file as proof that a previously launched native child has stopped.
func (i *Installation) recoverAbandoned(ctx context.Context, db *store.Store, epoch string) error {
	if i.OwnerLock == nil {
		return store.ErrCleanupPending
	}
	if err := i.RecoverWorkers(ctx, db, epoch); err != nil {
		return errors.Join(store.ErrCleanupPending, err)
	}
	if err := sandbox.ReconcileOffline(ctx, db, i.Root, epoch); err != nil {
		return errors.Join(store.ErrCleanupPending, err)
	}
	if err := i.recoverBackups(ctx, db, epoch); err != nil {
		return errors.Join(store.ErrCleanupPending, err)
	}
	if err := i.recoverGenerations(ctx, db, epoch); err != nil {
		return errors.Join(store.ErrCleanupPending, err)
	}
	return nil
}

func (i *Installation) recoverGenerations(ctx context.Context, db *store.Store, epoch string) error {
	preparations, err := db.Preparations(ctx)
	if err != nil {
		return err
	}
	images, err := db.Images(ctx)
	if err != nil {
		return err
	}
	if len(preparations) != 0 {
		current, err := db.Epoch(ctx, epoch)
		if err != nil {
			return err
		}
		settled := make(map[string]string)
		for _, img := range images {
			if ownedImage(img) && (img.State == store.Prepared || img.State == store.Published) {
				// The durable stage proof includes observed writer exit.
				settled[img.PreparationID] = img.EpochID
			}
		}
		for _, p := range preparations {
			if !ownedPreparation(p) || p.EpochID == epoch || p.State != store.CleanupPending {
				return store.ErrCleanupPending
			}
			if settled[p.ID] == p.EpochID {
				continue
			}
			previous, err := db.Epoch(ctx, p.EpochID)
			if err != nil {
				return err
			}
			if previous.BootID == "" || current.BootID == "" || previous.BootID == current.BootID {
				return fmt.Errorf("%w: preparation %s has no native exit evidence", store.ErrCleanupPending, p.ID)
			}
		}
	}
	for _, img := range images {
		if img.State == store.Published || img.State == store.Prepared {
			continue
		}
		if !ownedImage(img) || img.EpochID == epoch || img.State != store.CleanupPending {
			return store.ErrCleanupPending
		}
		// A linked prep has passed the native boot boundary above; if it
		// was released in its original epoch the writer was already settled.
		if err := db.MarkImagePending(ctx, epoch, img.ID); err != nil {
			return err
		}
		if err := removeMaintenanceDirectory(i.Root, img.Path); err != nil {
			return err
		}
		draft := draftName(img.ID)
		if err := errors.Join(removeMaintenanceFile(i.Root, draft), removeMaintenanceFile(i.Root, ".writing-"+draft)); err != nil {
			return err
		}
		if err := errors.Join(absent(i.Root, img.Path), absent(i.Root, draft), absent(i.Root, ".writing-"+draft)); err != nil {
			return err
		}
		if err := db.ReleaseImage(ctx, epoch, img.ID, removed); err != nil {
			return err
		}
	}
	for _, p := range preparations {
		job := filepath.Join(i.Path, filepath.FromSlash(p.Path))
		if err := preparehost.RemoveEndpoint(job, p.EpochID, p.ID); err != nil {
			return err
		}
		if err := removeMaintenanceDirectory(i.Root, p.Path); err != nil {
			return err
		}
		if err := absent(i.Root, p.Path); err != nil {
			return err
		}
		if err := releasePreparation(ctx, db, epoch, p.ID); err != nil {
			return err
		}
	}
	return nil
}

func (i *Installation) recoverBackups(ctx context.Context, db *store.Store, epoch string) error {
	backups, err := db.Backups(ctx)
	if err != nil {
		return err
	}
	for _, b := range backups {
		if b.State == store.Verified && !b.UpdatePending {
			continue
		}
		if b.EpochID == epoch || (b.State != store.CleanupPending && (b.State != store.Verified || !b.UpdatePending)) {
			return store.ErrCleanupPending
		}
		if err := i.abandonBackup(ctx, db, epoch, b); err != nil {
			return err
		}
	}
	return nil
}

// Backups and the candidate code are written synchronously by the offline
// owner, with no child. A held new owner lock plus the exact durable record
// authorizes cleanup; a completed historical backup is never handled here.
func (i *Installation) abandonBackup(ctx context.Context, db *store.Store, epoch string, b store.Backup) error {
	if !ownedBackup(b, i.Manifest) {
		return store.ErrApprovalMismatch
	}
	if err := db.MarkBackupPending(ctx, epoch, b.ID); err != nil {
		return err
	}
	d, err := maintenanceDirectoryAt(i.Root, b.Path, false)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err == nil {
		err := i.verifyAbandonedBackup(ctx, d, b)
		if err == nil {
			err = emptyAbandonedBackup(d)
		}
		if err := errors.Join(err, d.Close()); err != nil {
			return err
		}
	}
	if err := removeMaintenanceDirectory(i.Root, b.Path); err != nil {
		return err
	}
	if err := absent(i.Root, b.Path); err != nil {
		return err
	}
	return db.ReleaseBackup(ctx, epoch, b.ID, removed)
}

func (i *Installation) verifyAbandonedBackup(ctx context.Context, backup *os.Root, b store.Backup) error {
	expected, err := backupOwnerDocument(b)
	if err != nil {
		return err
	}
	owner, err := readDocument(backup, backupOwnerName)
	if errors.Is(err, fs.ErrNotExist) {
		// A crash at generation creation or after the last meaningful entry
		// was removed may leave just the incomplete owner marker.
		names, err := maintenanceNames(backup)
		for _, name := range names {
			if name != ".writing-"+backupOwnerName {
				return store.ErrCleanupPending
			}
		}
		return err
	}
	if err != nil || !bytes.Equal(owner, expected) {
		return errors.Join(store.ErrApprovalMismatch, err)
	}
	next, err := decodeManifest(backup, backupIntent, i.Manifest.ID)
	if errors.Is(err, fs.ErrNotExist) {
		return absent(backup, backupPublishID)
	}
	if err != nil {
		return err
	}
	if identity(next).Target != b.Target || next.Bundle.Digest == b.BundleDigest || next.PlanDigest == b.PlanDigest || !b.ForUpdate || next.CodeDir == i.Manifest.CodeDir {
		return store.ErrApprovalMismatch
	}
	pinned, err := readDocument(backup, backupPublishID)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // Staging did not register a candidate for publication.
	}
	if err != nil {
		return err
	}
	if present, err := maintenanceDirPresent(backup, backupStage); err != nil || present {
		return err // Rename did not complete; no destination was authorized.
	}
	actual, err := maintenanceDirectoryIdentity(i.Root, next.CodeDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // It was already removed in an earlier recovery attempt.
	}
	if err != nil || actual != string(pinned) {
		return errors.Join(store.ErrApprovalMismatch, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return removeMaintenanceDirectory(i.Root, next.CodeDir)
}

func emptyAbandonedBackup(backup *os.Root) error {
	names, err := maintenanceNames(backup)
	if err != nil {
		return err
	}
	// Keep the owner marker until the last removal. Otherwise an
	// interrupted cleanup could no longer prove ownership on restart.
	for _, name := range names {
		if name == backupOwnerName || name == backupIntent || name == backupPublishID {
			continue
		}
		if err := removeMaintenancePath(backup, name); err != nil {
			return err
		}
	}
	for _, name := range []string{backupPublishID, backupIntent, backupOwnerName} {
		if err := removeMaintenanceFile(backup, name); err != nil {
			return err
		}
	}
	return nil
}

func (i *Installation) refuseExecutableIn(paths []string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	for _, name := range paths {
		target := filepath.Join(i.Path, filepath.FromSlash(name))
		if rel, err := filepath.Rel(target, executable); err == nil && filepath.IsLocal(rel) {
			return errors.New("refusing to delete a path containing the running launcher; use the downloaded launcher outside the installation")
		}
	}
	return nil
}
