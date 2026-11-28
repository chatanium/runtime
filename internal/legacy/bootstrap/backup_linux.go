//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/legacy/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
)

func backupInstallation(ctx context.Context, s *ownedSession, backupID string) error {
	m := s.manifest
	if _, e := host.VerifyDetached(ctx, m); e != nil {
		return e
	}
	base := filepath.Join(m.Paths.Installation, "backup-"+backupID)
	journalPath := base + ".sqlite"
	imagePath := base + ".xfs"
	manifestPath := base + ".json"
	journalProps := host.ProvisionProperties{Path: journalPath, Source: filepath.Join(m.Paths.Control, "supervisor.sqlite"), Revision: m.ActiveRevision, ProductCreated: true}
	journal, e := backupRecord(ctx, s.store, "config", journalPath, journalProps)
	if e != nil {
		return e
	}
	if journal.State != "OBSERVED" {
		if e = s.store.BackupTo(ctx, journalPath); e != nil {
			return e
		}
		if e = observeHashedFile(ctx, s.store, journal.ID, journalPath, journalProps); e != nil {
			return e
		}
	}
	imageProps := host.ProvisionProperties{Path: imagePath, Source: m.Paths.BackingFile, SizeBytes: m.Backing.SizeBytes, UUID: m.Backing.XFSUUID, Revision: m.ActiveRevision, Mode: 0600, ProductCreated: true}
	image, e := backupRecord(ctx, s.store, "backing", imagePath, imageProps)
	if e != nil {
		return e
	}
	if image.State != "OBSERVED" {
		if e = copyProtectedFile(ctx, m.Paths.BackingFile, imagePath, m.Backing.SizeBytes); e != nil {
			return e
		}
		if e = observeHashedFile(ctx, s.store, image.ID, imagePath, imageProps); e != nil {
			return e
		}
	}
	raw, e := json.Marshal(m)
	if e != nil {
		return e
	}
	if _, e = updateStagedFile(ctx, s.store, manifestPath, raw, 0600); e != nil {
		return e
	}
	revision, e := s.store.Revision(ctx, m.ActiveRevision)
	if e != nil {
		return e
	}
	for _, id := range append([]string{m.BundleDigest}, backupGenerationIDs(revision)...) {
		if e = s.store.RetainGeneration(ctx, "recovery", id, "backup-"+backupID); e != nil {
			return e
		}
	}
	return nil
}

// A durable intent authorizes only this transaction's exact backup destination.
// Completed receipts are rehashed, and retired receipts never authorize creation.
func backupRecord(ctx context.Context, s *host.Store, kind, path string, p host.ProvisionProperties) (host.ProvisionRecord, error) {
	records, e := s.ObjectProvisions(ctx, kind, path)
	if e != nil {
		return host.ProvisionRecord{}, e
	}
	want := string(provisionJSON(p))
	for _, r := range records {
		if r.Kind != kind || r.Identity != path {
			continue
		}
		if r.CleanupState == "COMPLETE" || !r.ProductCreated || r.ExistedBefore || string(r.Desired) != want {
			return host.ProvisionRecord{}, errors.New("backup destination has different or retired ownership")
		}
		if r.State == "OBSERVED" {
			if e = matchRecord(r); e != nil {
				return host.ProvisionRecord{}, e
			}
		}
		return r, nil
	}
	if _, e = os.Lstat(path); !os.IsNotExist(e) {
		return host.ProvisionRecord{}, errors.Join(e, errors.New("unowned backup destination already exists"))
	}
	id, e := recordIntent(ctx, s, kind, path, p, false)
	return host.ProvisionRecord{ProvisionIntent: host.ProvisionIntent{ID: id}, State: "INTENT"}, e
}

// Once BACKED_UP is durable, the source backing may contain newly rebuilt
// derivatives. Revalidate the original backup triple without copying current
// data over it or requiring the in-progress backing to be detached.
func verifyUpdateBackup(ctx context.Context, s *ownedSession, backupID string) error {
	m := s.manifest
	base := filepath.Join(m.Paths.Installation, "backup-"+backupID)
	raw, e := json.Marshal(m)
	if e != nil {
		return e
	}
	for _, item := range []struct {
		kind, path string
		properties host.ProvisionProperties
	}{
		{"config", base + ".sqlite", host.ProvisionProperties{Path: base + ".sqlite", Source: filepath.Join(m.Paths.Control, "supervisor.sqlite"), Revision: m.ActiveRevision, ProductCreated: true}},
		{"backing", base + ".xfs", host.ProvisionProperties{Path: base + ".xfs", Source: m.Paths.BackingFile, SizeBytes: m.Backing.SizeBytes, UUID: m.Backing.XFSUUID, Revision: m.ActiveRevision, Mode: 0600, ProductCreated: true}},
		{"config", base + ".json", host.ProvisionProperties{Path: base + ".json", Digest: provision.Digest(raw), Mode: 0600, ProductCreated: true}},
	} {
		records, e := s.store.ObjectProvisions(ctx, item.kind, item.path)
		if e != nil {
			return e
		}
		found := false
		for _, r := range records {
			if r.CleanupState == "COMPLETE" || !r.ProductCreated || r.ExistedBefore || r.State != "OBSERVED" || string(r.Desired) != string(provisionJSON(item.properties)) {
				return errors.New("update backup no longer has its exact completed receipt")
			}
			if e = matchRecord(r); e != nil {
				return e
			}
			found = true
		}
		if !found {
			return errors.New("completed update backup is missing its receipt")
		}
	}
	return nil
}
func backupGenerationIDs(r host.RevisionRecord) []string {
	ids := make([]string, 0, len(r.Images))
	seen := map[string]bool{}
	for _, image := range r.Images {
		if !seen[image.ImageRecordID] {
			ids = append(ids, image.ImageRecordID)
			seen[image.ImageRecordID] = true
		}
	}
	return ids
}
func observeHashedFile(ctx context.Context, s *host.Store, intent, path string, p host.ProvisionProperties) error {
	if e := trustedPath(path, false); e != nil {
		return e
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	p.Digest, e = streamDigest(f)
	if e != nil {
		return e
	}
	return observePath(ctx, s, intent, path, p)
}
func copyProtectedFile(ctx context.Context, source, destination string, max int64) error {
	if max <= 0 {
		return errors.New("finite backup size required")
	}
	if e := trustedPath(source, false); e != nil {
		return e
	}
	if e := trustedPath(destination, true); e != nil {
		return e
	}
	sourceFD, e := unix.Open(source, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	src := os.NewFile(uintptr(sourceFD), source)
	defer src.Close()
	var before unix.Stat_t
	if e = unix.Fstat(sourceFD, &before); e != nil {
		return e
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != 0 || before.Nlink != 1 || before.Size != max {
		return errors.New("backup source identity or size changed")
	}
	destinationFD, e := unix.Open(destination, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	dst := os.NewFile(uintptr(destinationFD), destination)
	defer dst.Close()
	slab := make([]byte, 256<<10)
	var partial unix.Stat_t
	if e = unix.Fstat(destinationFD, &partial); e != nil {
		return e
	}
	if partial.Mode&unix.S_IFMT != unix.S_IFREG || partial.Uid != 0 || partial.Nlink != 1 || partial.Mode&07777&^0600 != 0 || partial.Size > max {
		return errors.New("partial backup identity or size changed")
	}
	// Compare every already-written byte with the still-detached source before
	// continuing; an intent alone never proves a completed physical copy.
	comparison := make([]byte, len(slab))
	var copied int64
	for copied < partial.Size {
		if e = ctx.Err(); e != nil {
			return e
		}
		size := min(int64(len(slab)), partial.Size-copied)
		if _, e = io.ReadFull(src, slab[:size]); e != nil {
			return e
		}
		if _, e = io.ReadFull(dst, comparison[:size]); e != nil {
			return e
		}
		if !bytes.Equal(slab[:size], comparison[:size]) {
			return errors.New("partial backup differs from approved source")
		}
		copied += size
	}
	if e = unix.Fchmod(destinationFD, 0600); e != nil {
		return e
	}
	for copied < max {
		if e = ctx.Err(); e != nil {
			return e
		}
		size := int64(len(slab))
		if max-copied < size {
			size = max - copied
		}
		n, e := io.ReadFull(src, slab[:size])
		if n > 0 {
			written, writeErr := dst.Write(slab[:n])
			copied += int64(written)
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
		}
		if e != nil {
			return e
		}
	}
	var after unix.Stat_t
	if e = unix.Fstat(sourceFD, &after); e != nil {
		return e
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return errors.New("backup source changed during copy")
	}
	if e = dst.Sync(); e != nil {
		return e
	}
	if e = dst.Close(); e != nil {
		return e
	}
	parent, e := os.Open(filepath.Dir(destination))
	if e != nil {
		return e
	}
	defer parent.Close()
	return parent.Sync()
}
func beginRemoval(ctx context.Context, s *host.Store, r host.ProvisionRecord) (string, error) {
	if record, exists, e := removalFor(ctx, s, r); e != nil {
		return "", e
	} else if exists {
		return record.ID, nil
	}
	var p host.ProvisionProperties
	if e := gvxcontract.DecodeStrict(r.Observed.Attributes, 64<<10, 16, &p); e != nil {
		return "", e
	}
	p.Source = "remove"
	p.Revision = r.ID
	return recordIntent(ctx, s, r.Kind, r.Identity, p, true)
}
