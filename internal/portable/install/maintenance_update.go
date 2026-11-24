package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/portable/sandbox"
	"github.com/thirdscam/chatanium/internal/portable/store"
	"github.com/thirdscam/chatanium/internal/releasepayload"
)

const (
	backupOwnerName      = "owner.json"
	backupReceiptName    = "inventory.json"
	backupConfigName     = "config.json"
	discordOwnershipLeaf = "discord-ownership.sqlite"
)

type updatePlan struct {
	Format        string                  `json:"format"`
	Path          string                  `json:"installation"`
	Owner         string                  `json:"owner"`
	CurrentBundle string                  `json:"current_bundle"`
	CurrentPlan   string                  `json:"current_plan"`
	CurrentConfig string                  `json:"current_config"`
	NextConfig    string                  `json:"next_config"`
	NextBundle    bundle.PortableManifest `json:"next_bundle"`
	BackupPath    string                  `json:"backup_repository"`
	BudgetBytes   int64                   `json:"budget_bytes"`
	BackupBytes   int64                   `json:"backup_max_bytes"`
	Volumes       []store.Volume          `json:"persistent_volumes"`
	Images        []store.Image           `json:"referenced_images"`
	RetiredCode   []string                `json:"retired_code"`
	Members       []backupMember          `json:"backup_data_members"`
}

// Update replaces only the stopped, ledger-bound generation. The previously
// approved configuration, database, volume bytes and referenced cache are
// independently usable as a consistent backup before authority changes.
func Update(ctx context.Context, path string, confirm Confirm) (_ Manifest, resultErr error) {
	i, err := Lock(path)
	if err != nil {
		return Manifest{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, i.Close()) }()
	db, err := i.Store(ctx)
	if err != nil {
		return Manifest{}, err
	}
	defer func() {
		if db != nil {
			resultErr = errors.Join(resultErr, db.Close())
		}
	}()
	old := i.Manifest
	record, err := db.Installation(ctx)
	if err != nil {
		return Manifest{}, err
	}
	if err := matchMaintenanceManifest(record, old); err != nil {
		return Manifest{}, err
	}
	if record.State != store.Ready && record.State != store.Initializing {
		return Manifest{}, store.ErrState
	}
	nextBundle, err := releasepayload.InspectPortable()
	if err != nil {
		return Manifest{}, err
	}
	if nextBundle.Target.OS != old.Bundle.Target.OS || nextBundle.Target.Arch != old.Bundle.Target.Arch || nextBundle.Target.Backend != old.Bundle.Target.Backend {
		return Manifest{}, store.ErrApprovalMismatch
	}
	if err := i.verifyInstalledCode(ctx, old); err != nil {
		return Manifest{}, err
	}
	epoch, err := i.beginEpoch(ctx, db)
	if err != nil {
		return Manifest{}, err
	}
	defer func() {
		if db != nil {
			finishEpoch(ctx, db, epoch, &resultErr)
		}
	}()
	if err := i.recoverAbandoned(ctx, db, epoch); err != nil {
		return Manifest{}, err
	}
	if old.Bundle.Digest == nextBundle.Digest {
		return old, nil
	}
	if record.State != store.Ready {
		return Manifest{}, store.ErrState
	}
	if confirm == nil {
		return Manifest{}, errors.New("update requires exact PlanDigest approval")
	}
	backupInputs, err := i.inspectBackup(ctx, db, record)
	if err != nil {
		return Manifest{}, err
	}
	backups, err := db.Backups(ctx)
	if err != nil {
		return Manifest{}, err
	}
	retired, err := i.retiredCode(backups)
	if err != nil {
		return Manifest{}, err
	}
	code := codeDirectory(nextBundle.Digest)
	next := old
	next.State, next.Revision, next.ConfigPlanDigest = store.Initializing, "", ""
	next.Bundle, next.CodeDir, next.Modules = nextBundle, code, []Module{}
	next.Config, err = defaultConfig(old.ID, nextBundle.Digest, path)
	if err != nil {
		return Manifest{}, err
	}
	configDigest, err := documentDigest(next.Config)
	if err != nil {
		return Manifest{}, err
	}
	plan := updatePlan{Format: Format, Path: path, Owner: old.Owner, CurrentBundle: old.Bundle.Digest, CurrentPlan: old.PlanDigest, CurrentConfig: record.ConfigDigest, NextConfig: configDigest, NextBundle: nextBundle, BackupPath: filepath.Join(path, "backups"), BudgetBytes: old.BudgetBytes, BackupBytes: backupInputs.maxBytes, Volumes: backupInputs.volumes, Images: backupInputs.images, RetiredCode: retired, Members: backupInputs.files}
	next.PlanDigest, err = planDigest(plan)
	if err != nil {
		return Manifest{}, err
	}
	if err := confirm("Approve the stopped update, target bundle, and complete backup scope (PlanDigest)", plan, next.PlanDigest); err != nil {
		return Manifest{}, err
	}
	if err := ctx.Err(); err != nil {
		return Manifest{}, err
	}
	if raw, err := readDocument(i.Root, manifestName); err != nil || !bytes.Equal(raw, backupInputs.manifest) {
		return Manifest{}, errors.Join(store.ErrApprovalMismatch, err)
	}
	if err := i.refuseExecutableIn(append(append([]string(nil), retired...), old.CodeDir)); err != nil {
		return Manifest{}, err
	}
	for _, dir := range retired {
		if err := removeMaintenanceDirectory(i.Root, dir); err != nil {
			return Manifest{}, err
		}
	}
	if err := absent(i.Root, code); err != nil {
		return Manifest{}, err
	}
	codeBytes, err := bundleBytes(nextBundle)
	if err != nil {
		return Manifest{}, err
	}
	nextRaw, err := json.Marshal(next)
	if err != nil || len(nextRaw) > maxDocument {
		return Manifest{}, errors.Join(errors.New("next manifest exceeds its bound"), err)
	}
	if err := checkMetadataBudget(i, codeBytes+bundle.MaxManifestBytes+int64(len(nextRaw))); err != nil {
		return Manifest{}, err
	}
	b, err := db.BeginBackup(ctx, epoch, backupInputs.maxBytes, true)
	if err != nil {
		return Manifest{}, err
	}
	finished := false
	defer func() {
		if finished || db == nil || resultErr == nil {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		current, err := db.Installation(cleanup)
		if err == nil && current.InstallationIdentity == identity(old) && current.PlanDigest == old.PlanDigest {
			err = i.abandonBackup(cleanup, db, epoch, b)
		}
		if err != nil {
			resultErr = errors.Join(resultErr, store.ErrCleanupPending, err)
		}
	}()
	if !ownedBackup(b, old) || b.InstallationIdentity != identity(old) || b.ConfigDigest != record.ConfigDigest || b.ConfigRevision != record.ConfigRevision || b.PlanDigest != record.PlanDigest || !sameBackupInputs(b, backupInputs) {
		return Manifest{}, store.ErrApprovalMismatch
	}
	destination, err := maintenanceDirectoryAt(i.Root, b.Path, true)
	if err != nil {
		// An existing entry at the randomly reserved name is not ours.
		if errors.Is(err, os.ErrExist) {
			finished = true
			err = errors.Join(store.ErrCleanupPending, err)
		}
		return Manifest{}, err
	}
	// Register this close after the rollback defer, so no destination handle
	// is left open when rollback tries to remove it on Windows.
	defer func() { resultErr = errors.Join(resultErr, destination.Close()) }()
	owner, err := backupOwnerDocument(b)
	if err != nil {
		return Manifest{}, err
	}
	if err := writeNew(destination, backupOwnerName, owner); err != nil {
		return Manifest{}, err
	}
	if err := writeNew(destination, backupIntent, nextRaw); err != nil {
		return Manifest{}, err
	}
	if err := db.SnapshotDatabase(ctx, epoch, b.ID); err != nil {
		return Manifest{}, err
	}
	if err := i.copyBackup(ctx, db, epoch, b, destination, backupInputs); err != nil {
		return Manifest{}, err
	}
	if err := i.publishNextCode(ctx, destination, b, next); err != nil {
		return Manifest{}, err
	}
	if err := i.stageManifest(next); err != nil {
		return Manifest{}, err
	}
	proof := store.BackupProof{WritersExited: true, Verified: true, Synchronized: true}
	if err := db.CompleteBackup(ctx, epoch, b.ID, proof); err != nil {
		return Manifest{}, err
	}
	if err := db.FinishUpdate(ctx, epoch, b.ID, identity(next), next.PlanDigest); err != nil {
		return Manifest{}, err
	}
	finished = true
	if err := i.commitManifest(next); err != nil {
		return Manifest{}, errors.Join(store.ErrCleanupPending, err)
	}
	// Retire code only after the new executable inventory and complete manifest
	// are durable. Kept backups pin the old identity even if retirement fails.
	if err := removeMaintenanceDirectory(i.Root, old.CodeDir); err != nil {
		return next, errors.Join(store.ErrCleanupPending, err)
	}
	return next, nil
}

func matchMaintenanceManifest(record store.InstallationRecord, m Manifest) error {
	if record.InstallationIdentity != identity(m) || record.PlanDigest != m.PlanDigest || record.ConfigRevision != m.Revision || record.BudgetBytes != m.BudgetBytes || record.MetadataBytes != m.MetadataBytes || record.LogBytes != m.LogBytes {
		return store.ErrApprovalMismatch
	}
	digest, err := documentDigest(m.Config)
	if err != nil {
		return err
	}
	if record.ConfigDigest == "" && m.Revision == "" && len(m.Modules) == 0 || record.ConfigDigest == digest && m.Revision != "" {
		return nil
	}
	return store.ErrApprovalMismatch
}

type backupInputs struct {
	sqliteBytes, maxBytes int64
	manifest, config      []byte
	volumes               []store.Volume
	images                []store.Image
	files                 []backupMember
}

type backupMember struct {
	Path   string `json:"path"`
	Size   int64  `json:"logical_bytes"`
	Digest string `json:"digest"`
}

func (i *Installation) inspectBackup(ctx context.Context, db *store.Store, record store.InstallationRecord) (backupInputs, error) {
	var in backupInputs
	var err error
	in.sqliteBytes, err = store.SQLiteFileBudget(record.MetadataBytes)
	if err != nil {
		return in, err
	}
	in.manifest, err = readDocument(i.Root, manifestName)
	if err != nil {
		return in, err
	}
	in.config, err = canonicalJSON(i.Manifest.Config)
	if err != nil || hashBytes(in.config) != record.ConfigDigest {
		return in, errors.Join(store.ErrApprovalMismatch, err)
	}
	in.volumes, err = db.Volumes(ctx)
	if err != nil {
		return in, err
	}
	var charges []int64
	charges = append(charges, in.sqliteBytes, int64(len(in.manifest)), int64(len(in.config)), maxDocument, maxDocument, maxDocument)
	discord, err := i.inspectDiscordBackup(ctx)
	if err != nil {
		return in, err
	}
	if discord.Path != "" {
		in.files = append(in.files, discord)
		charges = append(charges, discord.Size)
	}
	for _, v := range in.volumes {
		if !ownedVolume(v) {
			return in, store.ErrApprovalMismatch
		}
		observed, err := sandbox.ObserveVolume(i.Root, v)
		if err != nil {
			return in, err
		}
		// This path deliberately makes a nonsparse copy. Reserve the full
		// approved ceiling, not the host's sparse allocation or st_blocks.
		charges = append(charges, v.MaxBytes)
		if observed.Exists {
			in.files = append(in.files, backupMember{Path: v.Path, Size: observed.SizeBytes})
		}
	}
	conf, err := db.Configuration(ctx)
	if err != nil {
		return in, err
	}
	if conf.Revision != record.ConfigRevision || conf.ConfigDigest != record.ConfigDigest || len(conf.Approvals) != len(i.Manifest.Modules) {
		return in, store.ErrApprovalMismatch
	}
	images, err := db.Images(ctx)
	if err != nil {
		return in, err
	}
	modules := make(map[string]Module, len(i.Manifest.Modules))
	for _, m := range i.Manifest.Modules {
		modules[m.ID] = m
	}
	byID := make(map[string]store.Image, len(images))
	for _, img := range images {
		byID[img.ID] = img
	}
	for _, approval := range conf.Approvals {
		module, ok := modules[approval.ModuleID]
		if !ok || !reflect.DeepEqual(module.Approval, approval) {
			return in, store.ErrApprovalMismatch
		}
		delete(modules, approval.ModuleID)
		g := module.Generation
		img, ok := byID[approval.ImageGeneration]
		if !ok || !ownedImage(img) || img.State != store.Published || img.EngineDigest != record.EngineDigest || img.Digest != approval.ImageDigest || g.ID != img.ID || g.Epoch != img.EpochID || filepath.ToSlash(g.Directory) != img.Path || g.SourceDigest != img.Digest {
			return in, store.ErrApprovalMismatch
		}
		review, err := g.ReviewDigest(json.RawMessage(module.ReviewJSON))
		if err != nil || review != approval.ReviewDigest {
			return in, errors.Join(store.ErrApprovalMismatch, err)
		}
		if img.MaxBytes == 0 {
			// This generation was already accounted for by another approval.
			continue
		}
		dir, err := maintenanceDirectoryAt(i.Root, img.Path, false)
		if err != nil {
			return in, err
		}
		if err := dir.Close(); err != nil {
			return in, err
		}
		if _, err := g.VerifiedLaunch(i.Root, g.Epoch); err != nil {
			return in, err
		}
		var size int64
		for _, f := range g.Files {
			if !maintenanceLeaf(f.Path) || f.Size > img.MaxBytes-size || f.Size <= 0 {
				return in, store.ErrBudgetExceeded
			}
			size += f.Size
			in.files = append(in.files, backupMember{Path: img.Path + "/" + f.Path, Size: f.Size, Digest: f.Digest})
		}
		charges = append(charges, img.MaxBytes)
		in.images = append(in.images, img)
		img.MaxBytes = 0
		byID[img.ID] = img
	}
	for _, n := range charges {
		if n < 0 || n > math.MaxInt64-in.maxBytes {
			return in, store.ErrBudgetExceeded
		}
		in.maxBytes += n
	}
	return in, nil
}

func sameBackupInputs(b store.Backup, in backupInputs) bool {
	if len(b.Volumes) != len(in.volumes) || len(b.Images) != len(in.images) {
		return false
	}
	vs := make(map[string]store.Volume, len(in.volumes))
	for _, v := range in.volumes {
		vs[v.ID] = v
	}
	for _, v := range b.Volumes {
		if vs[v.ID] != v {
			return false
		}
		delete(vs, v.ID)
	}
	is := make(map[string]store.Image, len(in.images))
	for _, img := range in.images {
		is[img.ID] = img
	}
	for _, img := range b.Images {
		if is[img.ID] != img {
			return false
		}
		delete(is, img.ID)
	}
	return true
}

func backupOwnerDocument(b store.Backup) ([]byte, error) {
	return json.Marshal(struct {
		Format, BackupID, EpochID, PlanDigest string
		Installation                          store.InstallationIdentity
	}{Format, b.ID, b.EpochID, b.PlanDigest, b.InstallationIdentity})
}

func (i *Installation) copyBackup(ctx context.Context, db *store.Store, epoch string, b store.Backup, dest *os.Root, in backupInputs) error {
	parts := make([]backupMember, 1, len(in.files)+3)
	volumes := make(map[string]store.Volume, len(in.volumes))
	for _, v := range in.volumes {
		volumes[v.Path] = v
	}
	bindings := make([]store.BackupVolumeBinding, 0, len(volumes))
	for _, raw := range []struct {
		name string
		data []byte
	}{{manifestName, in.manifest}, {backupConfigName, in.config}} {
		member, err := copyBackupMember(ctx, dest, backupMember{raw.name, int64(len(raw.data)), hashBytes(raw.data)}, bytes.NewReader(raw.data))
		if err != nil {
			return err
		}
		parts = append(parts, member)
	}
	if err := checkPurgeNamespace(i.Root, "app/discord", func(name string) bool { return name == discordOwnershipLeaf }); err != nil {
		return errors.Join(store.ErrCleanupPending, err)
	}
	for _, member := range in.files {
		f, err := maintenanceOpen(i.Root, member.Path)
		if err != nil {
			return err
		}
		v := volumes[member.Path]
		if v.ID != "" {
			srcID, err := maintenanceHandleIdentity(f)
			if err != nil || srcID != v.NativeID {
				return errors.Join(store.ErrApprovalMismatch, err, f.Close())
			}
		}
		copied, err := copyBackupMember(ctx, dest, member, f)
		if err := errors.Join(err, f.Close()); err != nil {
			return fmt.Errorf("backup %s: %w", member.Path, err)
		}
		parts = append(parts, copied)
		if v.ID != "" {
			backupFile, err := maintenanceOpen(dest, member.Path)
			if err != nil {
				return err
			}
			copyID, err := maintenanceHandleIdentity(backupFile)
			if err := errors.Join(err, backupFile.Close()); err != nil {
				return err
			}
			bindings = append(bindings, store.BackupVolumeBinding{VolumeID: v.ID, SourceNativeID: v.NativeID, NativeID: copyID, Digest: copied.Digest, SizeBytes: copied.Size})
		}
	}
	for _, img := range in.images {
		if err := freezeBackupImage(dest, img.Path); err != nil {
			return err
		}
	}
	if err := db.SealBackupSnapshot(ctx, epoch, b.ID, bindings); err != nil {
		return err
	}
	member, err := i.verifyBackupDatabase(ctx, dest, in.sqliteBytes)
	if err != nil {
		return err
	}
	parts[0] = member
	receipt, err := json.Marshal(parts)
	if err != nil || len(receipt) > maxDocument {
		return errors.Join(store.ErrBudgetExceeded, err)
	}
	return writeNew(dest, backupReceiptName, receipt)
}

func (i *Installation) verifyBackupDatabase(ctx context.Context, dest *os.Root, bound int64) (_ backupMember, resultErr error) {
	// Open the finished copy as an independent ledger. Then flush and hash
	// its exact logical bytes after all SQLite handles have closed.
	copied, err := store.Open(ctx, dest.Name(), identity(i.Manifest))
	if err != nil {
		return backupMember{}, err
	}
	record, err := copied.Installation(ctx)
	if err := errors.Join(err, copied.Close()); err != nil {
		return backupMember{}, err
	}
	if err := matchMaintenanceManifest(record, i.Manifest); err != nil {
		return backupMember{}, err
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if err := absent(dest, store.DatabaseName+suffix); err != nil {
			return backupMember{}, err
		}
	}
	readOnly, err := maintenanceOpen(dest, store.DatabaseName)
	if err != nil {
		return backupMember{}, err
	}
	info, err := readOnly.Stat()
	if err := errors.Join(err, readOnly.Close()); err != nil {
		return backupMember{}, err
	}
	if info.Size() <= 0 || info.Size() > bound {
		return backupMember{}, store.ErrBudgetExceeded
	}
	file, err := dest.OpenFile(store.DatabaseName, os.O_RDWR, 0)
	if err != nil {
		return backupMember{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	current, err := file.Stat()
	if err != nil || !os.SameFile(info, current) || current.Size() != info.Size() {
		return backupMember{}, errors.Join(store.ErrApprovalMismatch, err)
	}
	if err := file.Sync(); err != nil {
		return backupMember{}, err
	}
	h := sha256.New()
	n, err := io.Copy(h, maintenanceReader{ctx, io.LimitReader(file, info.Size()+1)})
	if err != nil || n != info.Size() {
		return backupMember{}, errors.Join(store.ErrApprovalMismatch, err)
	}
	return backupMember{store.DatabaseName, n, "sha256:" + hex.EncodeToString(h.Sum(nil))}, nil
}

func freezeBackupImage(root *os.Root, path string) error {
	image, err := maintenanceDirectoryAt(root, path, false)
	if err != nil {
		return err
	}
	return errors.Join(image.Chmod(".", 0555), syncDirectory(image), image.Close())
}

func copyBackupMember(ctx context.Context, dest *os.Root, m backupMember, src io.Reader) (backupMember, error) {
	parent, leaf, closeParent, err := maintenanceParent(dest, m.Path, true)
	if err != nil {
		return m, err
	}
	defer closeParent()
	f, err := parent.OpenFile(leaf, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return m, err
	}
	h := sha256.New()
	r := maintenanceReader{ctx, src}
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, m.Size))
	if err == nil && n != m.Size {
		err = io.ErrUnexpectedEOF
	}
	if err == nil {
		var extra [1]byte
		if _, e := io.ReadFull(r, extra[:]); e != io.EOF {
			err = errors.Join(store.ErrApprovalMismatch, e)
		}
	}
	digest := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if err == nil && m.Digest != "" && m.Digest != digest {
		err = store.ErrApprovalMismatch
	}
	mode := os.FileMode(0)
	if err == nil && strings.HasPrefix(m.Path, "images/") {
		mode = 0444
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if err := errors.Join(err, f.Close()); err != nil {
		return m, err
	}
	m.Digest = digest
	v, err := maintenanceOpen(parent, leaf)
	if err != nil {
		return m, err
	}
	if err := errors.Join(verifyMaintenanceFile(ctx, v, m.Size, m.Digest, mode), v.Close()); err != nil {
		return m, err
	}
	return m, syncDirectory(parent)
}

func (i *Installation) publishNextCode(ctx context.Context, dest *os.Root, b store.Backup, next Manifest) error {
	stage, err := maintenanceDirectoryAt(dest, backupStage, true)
	if err != nil {
		return err
	}
	got, err := releasepayload.ExtractPortable(ctx, stage)
	if err == nil && got.Digest != next.Bundle.Digest {
		err = store.ErrApprovalMismatch
	}
	if err == nil {
		got, err = releasepayload.VerifyPortable(ctx, stage)
		if err == nil && got.Digest != next.Bundle.Digest {
			err = store.ErrApprovalMismatch
		}
	}
	if err := errors.Join(err, stage.Close()); err != nil {
		return err
	}
	if err := absent(i.Root, next.CodeDir); err != nil {
		return err
	}
	nativeID, err := maintenanceDirectoryIdentity(dest, backupStage)
	if err != nil {
		return err
	}
	if err := writeNew(dest, backupPublishID, []byte(nativeID)); err != nil {
		return err
	}
	return publishMaintenanceCode(i.Root, dest, filepath.FromSlash(b.Path+"/"+backupStage), next.CodeDir)
}

// Only the active installation and historical ledger-pinned backup identities
// can authorize an installed code directory. Prefix matching alone is unsafe.
func (i *Installation) retiredCode(backups []store.Backup) ([]string, error) {
	known := make(map[string]bool, len(backups))
	for _, b := range backups {
		if b.State != store.Verified || b.UpdatePending || !ownedBackup(b, i.Manifest) {
			return nil, store.ErrCleanupPending
		}
		known[codeDirectory(b.BundleDigest)] = true
	}
	names, err := maintenanceNames(i.Root)
	if err != nil {
		return nil, err
	}
	var retired []string
	for _, name := range names {
		if !strings.HasPrefix(name, "code-") || name == i.Manifest.CodeDir {
			continue
		}
		if !known[name] {
			return nil, fmt.Errorf("refusing unknown installed code path %q", name)
		}
		if _, err := maintenanceDirPresent(i.Root, name); err != nil {
			return nil, err
		}
		retired = append(retired, name)
	}
	sort.Strings(retired)
	return retired, nil
}
