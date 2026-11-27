package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/sandbox"
	"github.com/thirdscam/chatanium/internal/portable/store"
	"github.com/thirdscam/chatanium/internal/runtime"
)

const restoreReceiptName = "restore-inventory.json"

// BindRestoredVolumes authorizes only a freshly staged sealed backup placed
// at the installation's approved path. The external receipt digest covers the
// copied SQLite bytes before binding; the SQLite transaction consumes its seal.
func BindRestoredVolumes(ctx context.Context, path, backupID, receiptDigest string) (result error) {
	if !generationPattern.MatchString(backupID) || !digestPattern.MatchString(receiptDigest) {
		return errors.New("restore requires the exact backup ID and trusted sha256: receipt digest")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	parent, err := anchor(path, false)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, parent.Close()) }()
	gate, err := process.Lock(filepath.Join(parent.Name(), anchorLock))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, gate.Close()) }()
	for _, name := range []string{purgeTerminalName(path), ".writing-" + purgeTerminalName(path)} {
		if err := absent(parent, name); err != nil {
			return errors.Join(store.ErrCleanupPending, err)
		}
	}
	root, err := privateChild(parent, filepath.Base(path), false)
	if err != nil {
		return err
	}
	i := &Installation{Path: path, Root: root}
	defer func() { result = errors.Join(result, i.Close()) }()
	// Do not use Lock: its routine manifest reconciliation may open SQLite or
	// publish a pending manifest before the external receipt is authenticated.
	i.OwnerLock, err = process.Lock(filepath.Join(path, ownerLock))
	if err != nil {
		return err
	}
	receipt, err := readRestoreDocument(root, restoreReceiptName)
	if err != nil || hashBytes(receipt) != receiptDigest {
		return errors.Join(store.ErrApprovalMismatch, err)
	}
	inventory, err := restoreInventory(receipt)
	if err != nil {
		return err
	}
	if _, err := verifiedRestoreMember(ctx, root, inventory[manifestName], false); err != nil {
		return err
	}
	i.Manifest, err = decodeManifest(root, manifestName, "")
	if err != nil {
		return err
	}
	if i.Manifest.State != store.Ready {
		return store.ErrState
	}
	if err := i.verifyRestoreRoot(); err != nil {
		return err
	}
	if err := i.verifyInstalledCode(ctx, i.Manifest); err != nil {
		return err
	}
	if err := checkMetadataBudget(i, 0); err != nil {
		return err
	}
	limit, err := store.SQLiteFileBudget(i.Manifest.MetadataBytes)
	if err != nil || inventory[store.DatabaseName].Size > limit {
		return errors.Join(store.ErrBudgetExceeded, err)
	}
	databaseCheck := verifyRestoreLedger(ctx, root, inventory[store.DatabaseName], limit)
	if databaseCheck != nil {
		if !errors.Is(databaseCheck, store.ErrApprovalMismatch) {
			return databaseCheck
		}
		// Only a proven, already-bound immutable ledger can differ from the
		// trusted archived bytes. Never open other mismatches read/write.
		completed, err := store.ProbeRestoreBinding(ctx, path, backupID, receiptDigest)
		if err != nil || !completed {
			return errors.Join(databaseCheck, err)
		}
	}
	config, err := readRestoreDocument(root, backupConfigName)
	if err != nil {
		return err
	}
	canonical, err := canonicalJSON(i.Manifest.Config)
	if err != nil || !bytes.Equal(canonical, config) || inventory[backupConfigName].Size != int64(len(config)) || inventory[backupConfigName].Digest != hashBytes(config) {
		return errors.Join(store.ErrApprovalMismatch, err)
	}
	delete(inventory, manifestName)
	delete(inventory, store.DatabaseName)
	delete(inventory, backupConfigName)

	db, err := i.Store(ctx)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, db.Close()) }()
	completed, err := db.RestoreBinding(ctx, backupID, receiptDigest)
	if err != nil {
		return errors.Join(databaseCheck, err)
	}
	if !completed && databaseCheck != nil {
		return databaseCheck
	}
	record, err := db.Installation(ctx)
	if err != nil {
		return err
	}
	if err := matchMaintenanceManifest(record, i.Manifest); err != nil {
		return err
	}
	if record.State != store.Ready || record.Desired != store.DesiredStopped || record.WorkerPending {
		return store.ErrCleanupPending
	}
	bindings, err := i.verifyRestoredVolumes(ctx, db, inventory, completed)
	if err != nil {
		return err
	}
	if err := i.verifyRestoredImages(ctx, db, record, inventory); err != nil {
		return err
	}
	if err := i.verifyRestoredDiscord(ctx, inventory); err != nil {
		return err
	}
	if len(inventory) != 0 {
		return fmt.Errorf("%w: restore receipt has entries outside the approved installation", store.ErrApprovalMismatch)
	}
	if err := errors.Join(syncDirectory(root), syncDirectory(parent)); err != nil {
		return err
	}
	// The ledger records the digest and state atomically. Leave both audit
	// leaves intact; retries authenticate the stored digest instead of
	// comparing the already-rebound ledger to its original bytes.
	if completed {
		return nil
	}
	return db.RebindRestoredVolumes(ctx, backupID, receiptDigest, bindings)
}

func restoreInventory(raw []byte) (map[string]backupMember, error) {
	var parts []backupMember
	if err := gvxcontract.DecodeStrict(raw, maxDocument, 8, &parts); err != nil {
		return nil, err
	}
	out := make(map[string]backupMember, len(parts))
	for _, member := range parts {
		for part := range strings.SplitSeq(member.Path, "/") {
			if !maintenanceLeaf(part) {
				return nil, store.ErrApprovalMismatch
			}
		}
		if member.Size < 0 || member.Size == 0 && member.Path != discordOwnershipPath || member.Size == 1<<63-1 ||
			!digestPattern.MatchString(member.Digest) || out[member.Path].Path != "" {
			return nil, store.ErrApprovalMismatch
		}
		out[member.Path] = member
	}
	for _, name := range []string{store.DatabaseName, manifestName, backupConfigName} {
		if out[name].Path == "" || name != store.DatabaseName && out[name].Size > maxDocument {
			return nil, store.ErrApprovalMismatch
		}
	}
	return out, nil
}

func (i *Installation) verifyRestoreRoot() error {
	names, err := maintenanceNames(i.Root)
	if err != nil {
		return err
	}
	for _, name := range names {
		switch name {
		case i.Manifest.CodeDir, store.DatabaseName, manifestName, backupConfigName, restoreReceiptName, ownerLock,
			"volumes", "images", "ipc", "app", "instances", "preparations", "backups":
		default:
			return fmt.Errorf("%w: unexpected path in freshly restored installation: %q", store.ErrApprovalMismatch, name)
		}
	}
	for _, name := range []string{"ipc", "instances", "preparations", "backups", "app/uploads"} {
		if err := checkPurgeNamespace(i.Root, name, func(string) bool { return false }); err != nil {
			return err
		}
	}
	cfg, err := runtime.DecodeConfig(i.Manifest.Config)
	if err != nil {
		return err
	}
	managedToken := cfg.Backends["discord"].SecretSources["bot_token"] == i.discordTokenSource()
	if err := checkPurgeNamespace(i.Root, "app", func(name string) bool {
		return name == "uploads" || name == "discord" || managedToken && name == discordTokenLeaf
	}); err != nil {
		return err
	}
	if managedToken {
		if _, err := i.Root.Lstat("app/" + discordTokenLeaf); !errors.Is(err, fs.ErrNotExist) {
			if err != nil {
				return err
			}
			file := filepath.Join(i.Path, "app", discordTokenLeaf)
			token, err := readDiscordTokenFile(file, false)
			clear(token)
			if err != nil {
				return err
			}
		}
	}
	for _, name := range []string{"app", "app/uploads", "app/discord", "ipc"} {
		if err := process.CheckPrivateDir(filepath.Join(i.Path, filepath.FromSlash(name))); err != nil {
			return err
		}
	}
	return nil
}

func (i *Installation) verifyRestoredVolumes(ctx context.Context, db *store.Store, inventory map[string]backupMember, completed bool) ([]store.BackupVolumeBinding, error) {
	volumes, err := db.Volumes(ctx)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(volumes))
	bindings := make([]store.BackupVolumeBinding, 0, len(volumes))
	for _, volume := range volumes {
		if !ownedVolume(volume) {
			return nil, store.ErrApprovalMismatch
		}
		if !volume.Initialized {
			if _, err := sandbox.ObserveVolume(i.Root, volume); err != nil {
				return nil, err
			}
			continue
		}
		member := inventory[volume.Path]
		if volume.NativeID == "" || member.Size < store.MinVolumeBytes || member.Size > volume.MaxBytes || member.Size%store.VolumeAlignmentBytes != 0 {
			return nil, store.ErrApprovalMismatch
		}
		nativeID, err := verifiedRestoreMember(ctx, i.Root, member, true)
		if err != nil {
			return nil, err
		}
		source := volume.NativeID
		if completed && source != nativeID {
			return nil, store.ErrApprovalMismatch
		}
		volume.NativeID = nativeID
		observation, err := sandbox.ObserveVolume(i.Root, volume)
		if err != nil || observation.SizeBytes != member.Size {
			return nil, errors.Join(store.ErrApprovalMismatch, err)
		}
		bindings = append(bindings, store.BackupVolumeBinding{VolumeID: volume.ID, SourceNativeID: source, NativeID: nativeID, Digest: member.Digest, SizeBytes: member.Size})
		allowed[filepath.Base(volume.Path)] = true
		delete(inventory, volume.Path)
	}
	if err := checkPurgeNamespace(i.Root, "volumes", func(name string) bool { return allowed[name] }); err != nil {
		return nil, err
	}
	return bindings, nil
}

func (i *Installation) verifyRestoredImages(ctx context.Context, db *store.Store, record store.InstallationRecord, inventory map[string]backupMember) error {
	config, err := db.Configuration(ctx)
	if err != nil {
		return err
	}
	if config.Revision != record.ConfigRevision || config.ConfigDigest != record.ConfigDigest || len(config.Approvals) != len(i.Manifest.Modules) {
		return store.ErrApprovalMismatch
	}
	images, err := db.Images(ctx)
	if err != nil {
		return err
	}
	byID := make(map[string]store.Image, len(images))
	for _, image := range images {
		byID[image.ID] = image
	}
	approvals := make(map[string]store.Approval, len(config.Approvals))
	for _, approval := range config.Approvals {
		approvals[approval.ModuleID] = approval
	}
	checked := make(map[string]string, len(images))
	epochs := make(map[string]map[string]bool)
	for _, module := range i.Manifest.Modules {
		approval := approvals[module.ID]
		g := module.Generation
		image := byID[approval.ImageGeneration]
		if !reflect.DeepEqual(approval, module.Approval) || !ownedImage(image) || image.State != store.Published || image.EngineDigest != record.EngineDigest || image.Digest != approval.ImageDigest || g.SourceDigest != image.Digest || g.ID != image.ID || g.Epoch != image.EpochID || g.Directory != image.Path {
			return store.ErrApprovalMismatch
		}
		delete(approvals, module.ID)
		if prior := checked[image.ID]; prior != "" {
			if prior != g.Digest {
				return store.ErrApprovalMismatch
			}
			continue
		}
		var size int64
		for _, file := range g.Files {
			name := image.Path + "/" + file.Path
			member := inventory[name]
			if member.Digest != file.Digest || member.Size != file.Size || member.Size > image.MaxBytes-size {
				return store.ErrApprovalMismatch
			}
			// Check ownership and mount confinement before reading immutable bytes.
			f, err := maintenanceOpen(i.Root, name)
			if err != nil {
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			size += file.Size
			delete(inventory, name)
		}
		if _, err := g.VerifiedLaunch(i.Root, g.Epoch); err != nil {
			return err
		}
		checked[image.ID] = g.Digest
		if epochs[image.EpochID] == nil {
			epochs[image.EpochID] = make(map[string]bool)
		}
		epochs[image.EpochID][image.ID] = true
	}
	if len(approvals) != 0 || len(checked) != len(images) {
		return store.ErrApprovalMismatch
	}
	if err := checkPurgeNamespace(i.Root, "images", func(epoch string) bool { return epochs[epoch] != nil }); err != nil {
		return err
	}
	for epoch, images := range epochs {
		if err := checkPurgeNamespace(i.Root, "images/"+epoch, func(image string) bool { return images[image] }); err != nil {
			return err
		}
	}
	return nil
}

func (i *Installation) verifyRestoredDiscord(ctx context.Context, inventory map[string]backupMember) error {
	member := inventory[discordOwnershipPath]
	if err := checkPurgeNamespace(i.Root, "app/discord", func(name string) bool { return member.Path != "" && name == discordOwnershipLeaf }); err != nil {
		return err
	}
	if member.Path == "" {
		return nil
	}
	if member.Size > reservedDiscordBytes {
		return store.ErrBudgetExceeded
	}
	if _, err := verifiedRestoreMember(ctx, i.Root, member, true); err != nil {
		return err
	}
	delete(inventory, discordOwnershipPath)
	return nil
}

func readRestoreDocument(root *os.Root, name string) (_ []byte, result error) {
	file, err := maintenanceOpen(root, name)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	if err := process.CheckPrivateFileACL(file); err != nil {
		return nil, err
	}
	return readBounded(file)
}

func verifyRestoreLedger(ctx context.Context, root *os.Root, member backupMember, maxBytes int64) (result error) {
	file, err := maintenanceOpen(root, member.Path)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	if err := process.CheckPrivateFileACL(file); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() <= 0 || info.Size() > maxBytes {
		return store.ErrBudgetExceeded
	}
	if err := verifyMaintenanceFile(ctx, file, member.Size, member.Digest, 0); err != nil {
		return err
	}
	return syncRestoreMember(root, member, file)
}

// Verified bytes and native identity come from the same confined handle. A
// separate write-capable handle is needed for FlushFileBuffers on Windows;
// compare its binding before synchronizing and never write through it.
func verifiedRestoreMember(ctx context.Context, root *os.Root, member backupMember, durable bool) (_ string, result error) {
	f, err := maintenanceOpen(root, member.Path)
	if err != nil {
		return "", err
	}
	defer func() { result = errors.Join(result, f.Close()) }()
	if err := process.CheckPrivateFileACL(f); err != nil {
		return "", err
	}
	if err := verifyMaintenanceFile(ctx, f, member.Size, member.Digest, 0); err != nil {
		return "", err
	}
	id, err := maintenanceHandleIdentity(f)
	if err != nil || !durable {
		return id, err
	}
	return id, syncRestoreMember(root, member, f)
}

func syncRestoreMember(root *os.Root, member backupMember, f *os.File) (result error) {
	parent, leaf, closeParent, err := maintenanceParent(root, member.Path, false)
	if err != nil {
		return err
	}
	defer closeParent()
	writable, err := parent.OpenFile(leaf, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, writable.Close()) }()
	before, err := f.Stat()
	if err != nil {
		return err
	}
	after, err := writable.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != member.Size {
		return errors.Join(store.ErrApprovalMismatch, err)
	}
	if err := writable.Sync(); err != nil {
		return err
	}
	return syncDirectory(parent)
}
