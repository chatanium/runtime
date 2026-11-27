package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/sandbox"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

// Uninstall removes only installed code. All configuration, backups, image
// cache generations, persistent volumes and associated ledger charges remain.
func Uninstall(ctx context.Context, path string) (_ Manifest, resultErr error) {
	i, err := Lock(path)
	if err != nil {
		return Manifest{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, i.Close()) }()
	db, err := i.Store(ctx)
	if err != nil {
		return Manifest{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, db.Close()) }()
	record, err := db.Installation(ctx)
	if err != nil {
		return Manifest{}, err
	}
	if err := matchMaintenanceManifest(record, i.Manifest); err != nil {
		return Manifest{}, err
	}
	switch record.State {
	case store.Ready, store.Initializing, store.Uninstalling, store.Uninstalled:
	default:
		return Manifest{}, store.ErrState
	}
	epoch, err := i.beginEpoch(ctx, db)
	if err != nil {
		return Manifest{}, err
	}
	defer finishEpoch(ctx, db, epoch, &resultErr)
	if err := i.recoverAbandoned(ctx, db, epoch); err != nil {
		return Manifest{}, err
	}
	backups, err := db.Backups(ctx)
	if err != nil {
		return Manifest{}, err
	}
	code, err := i.retiredCode(backups)
	if err != nil {
		return Manifest{}, err
	}
	code = append(code, i.Manifest.CodeDir)
	if err := i.refuseExecutableIn(code); err != nil {
		return Manifest{}, err
	}
	if record.State == store.Ready || record.State == store.Initializing {
		if err := i.verifyInstalledCode(ctx, i.Manifest); err != nil {
			return Manifest{}, err
		}
	}
	for _, dir := range code {
		if err := maintenanceTree(i.Root, dir, false); err != nil {
			return Manifest{}, err
		}
	}
	if err := db.BeginUninstall(ctx, epoch); err != nil {
		return Manifest{}, err
	}
	for _, dir := range code {
		if err := errors.Join(removeMaintenanceDirectory(i.Root, dir), absent(i.Root, dir)); err != nil {
			return Manifest{}, errors.Join(store.ErrCleanupPending, err)
		}
	}
	if i.Manifest.State == store.Uninstalled {
		return i.Manifest, nil
	}
	next := i.Manifest
	next.State = store.Uninstalled
	if err := i.stageManifest(next); err != nil {
		return Manifest{}, err
	}
	if err := db.CompleteUninstall(ctx, epoch, removed); err != nil {
		return Manifest{}, err
	}
	if err := i.commitManifest(next); err != nil {
		return Manifest{}, err
	}
	return next, nil
}

const purgeIntent = "purge.json"

func purgeTerminalName(path string) string { return ".purge-" + filepath.Base(path) + ".json" }

type purgeScope struct {
	Format          string          `json:"format"`
	Root            string          `json:"installation_directory"`
	RootNativeID    string          `json:"installation_native_id"`
	ParentRetained  string          `json:"shared_parent_retained"`
	Owner           string          `json:"owner"`
	ConfigDigest    string          `json:"config_document_digest"`
	ManifestDigest  string          `json:"installation_manifest_digest"`
	Ledger          store.PurgePlan `json:"ledger"`
	Remove          []string        `json:"remove_relative_paths"`
	Entries         []purgeEntry    `json:"remove_members"`
	RestoreAudit    []backupMember  `json:"restored_audit_members,omitempty"`
	Finalize        []string        `json:"finalize_relative_paths"`
	TerminalReceipt string          `json:"temporary_parent_receipt"`
}

type purgeEntry struct {
	Path     string `json:"path"`
	NativeID string `json:"native_id"`
}

// Purge requires a confirmation over the ledger inventory and every
// installation path that may be removed. The shared management lock is held
// until final native removal, including after the installation lock closes.
func Purge(ctx context.Context, path string, confirm Confirm) (resultErr error) {
	if confirm == nil {
		return errors.New("purge requires exact deletion-scope digest approval")
	}
	parent, err := anchor(path, false)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, parent.Close()) }()
	gate, err := process.Lock(filepath.Join(parent.Name(), anchorLock))
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, gate.Close()) }()
	if err := requireDownloadedLauncher(path); err != nil {
		return err
	}
	if resumed, err := checkPurgeReceipt(ctx, parent, path, confirm); err != nil || resumed {
		return err
	}
	return purgeLocked(ctx, parent, path, "", func(scope purgeScope) error {
		return approvePurge(ctx, scope, confirm)
	})
}

// purgeLocked uses the singleton's held management lock. A reset is a fresh
// purge of an exact, already stopped installation, not a recovery request.
func purgeLocked(ctx context.Context, parent *os.Root, path, expectedID string, approve func(purgeScope) error) (resultErr error) {
	replacing := expectedID != ""
	root, err := maintenanceDir(parent, filepath.Base(path))
	if errors.Is(err, fs.ErrNotExist) {
		if replacing {
			return fmt.Errorf("%w: installation to replace is missing", store.ErrApprovalMismatch)
		}
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	var i *Installation
	if replacing {
		i, err = lockResetInstallation(parent, path, expectedID)
	} else {
		i, err = lockInstallation(parent, path)
	}
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, i.Close()) }()
	var resetFiles [3]fs.FileInfo
	if replacing {
		resetFiles, err = resetFinalizeFiles(i.Root)
		if err != nil {
			return err
		}
		if err := checkMaintenanceFile(i.Root, store.DatabaseName); err != nil {
			return err
		}
	}
	db, err := i.Store(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if db != nil {
			resultErr = errors.Join(resultErr, db.Close())
		}
	}()
	record, err := db.Installation(ctx)
	if err != nil {
		return err
	}
	if replacing {
		switch record.State {
		case store.Initializing, store.Ready, store.Uninstalled:
			if record.State != i.Manifest.State {
				return store.ErrApprovalMismatch
			}
			if record.State != store.Uninstalled {
				if err := i.verifyInstalledCode(ctx, i.Manifest); err != nil {
					return err
				}
			}
		case store.Purging, store.Purged:
			return pendingResetPurge()
		default:
			return store.ErrState
		}
	}
	if record.State != store.Purged {
		if err := matchMaintenanceManifest(record, i.Manifest); err != nil {
			return err
		}
	}
	var epoch string
	defer func() {
		if db != nil && epoch != "" {
			finishEpoch(ctx, db, epoch, &resultErr)
		}
	}()
	if !replacing && record.State != store.Purged {
		epoch, err = i.beginEpoch(ctx, db)
		if err != nil {
			return err
		}
		if record.State != store.Purging {
			if err := i.recoverAbandoned(ctx, db, epoch); err != nil {
				return err
			}
		}
	}
	var scope purgeScope
	if record.State == store.Purging || record.State == store.Purged {
		scope, err = readPurgeScope(i.Root, purgeIntent, path)
		if err == nil && scope.Ledger.Digest != record.PurgeDigest {
			err = store.ErrApprovalMismatch
		}
	} else {
		scope, err = i.collectPurge(ctx, db)
	}
	if err != nil {
		return err
	}
	if err := scope.checkRoot(parent, root, path); err != nil {
		return err
	}
	if err := scope.checkManifest(i.Root, i.Manifest); err != nil {
		return err
	}
	if err := i.validatePurge(ctx, scope, record.State == store.Purging || record.State == store.Purged); err != nil {
		return err
	}
	if err := approve(scope); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := scope.checkRoot(parent, root, path); err != nil {
		return err
	}
	if replacing {
		if err := checkResetContents(i.Root); err != nil {
			return err
		}
		currentFiles, err := resetFinalizeFiles(i.Root)
		if err != nil {
			return err
		}
		for n, file := range currentFiles {
			if !os.SameFile(resetFiles[n], file) {
				return store.ErrApprovalMismatch
			}
		}
		currentRecord, err := db.Installation(ctx)
		if err != nil {
			return err
		}
		if currentRecord != record {
			return store.ErrApprovalMismatch
		}
		current, err := i.collectPurge(ctx, db)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(scope, current) {
			return store.ErrApprovalMismatch
		}
	}
	if err := scope.checkManifest(i.Root, i.Manifest); err != nil {
		return err
	}
	if err := i.validatePurge(ctx, scope, record.State == store.Purging || record.State == store.Purged); err != nil {
		return err
	}
	if record.State != store.Purging && record.State != store.Purged {
		raw, err := json.Marshal(scope)
		if err != nil || len(raw) > maxDocument {
			return errors.Join(store.ErrBudgetExceeded, err)
		}
		if err := checkMetadataBudget(i, 2*int64(len(raw))); err != nil {
			return err
		}
		if replacing {
			epoch, err = i.beginEpoch(ctx, db)
			if err != nil {
				return err
			}
		}
		if err := removeMaintenanceFile(i.Root, purgeIntent); err != nil {
			return err
		}
		if err := writeNew(i.Root, purgeIntent, raw); err != nil {
			return err
		}
	}
	if record.State != store.Purged {
		p, err := db.BeginPurge(ctx, epoch, scope.Ledger.Digest)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(p, scope.Ledger) {
			return store.ErrApprovalMismatch
		}
		for _, name := range scope.Remove {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := errors.Join(removeMaintenancePath(i.Root, name), absent(i.Root, name)); err != nil {
				return errors.Join(store.ErrCleanupPending, err)
			}
		}
		if err := db.CompletePurge(ctx, epoch, scope.Ledger.Digest, removed); err != nil {
			return err
		}
		finishEpoch(ctx, db, epoch, &resultErr)
		epoch = ""
		if resultErr != nil {
			return resultErr
		}
	}
	if err := db.Close(); err != nil {
		db = nil
		return err
	}
	db = nil
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if err := absent(i.Root, store.DatabaseName+suffix); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(scope)
	if err != nil {
		return err
	}
	if err := writeNew(parent, purgeTerminalName(path), raw); err != nil {
		return err
	}
	if err := i.Close(); err != nil {
		return err
	}
	return finishNativePurge(parent, root, path, scope)
}

func requireDownloadedLauncher(root string) error {
	name, err := os.Executable()
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, name)
	if err == nil && filepath.IsLocal(rel) {
		return errors.New("purge must run from the downloaded launcher outside the installation")
	}
	return nil
}

func approvePurge(ctx context.Context, p purgeScope, confirm Confirm) error {
	digest, err := planDigest(p)
	if err != nil {
		return err
	}
	if err := confirm("Permanently delete only the listed installed files, configuration and retained data (PurgeDigest)", p, digest); err != nil {
		return err
	}
	return ctx.Err()
}

func (i *Installation) collectPurge(ctx context.Context, db *store.Store) (purgeScope, error) {
	p, err := db.PlanPurge(ctx)
	if err != nil {
		return purgeScope{}, err
	}
	manifest, err := readDocument(i.Root, manifestName)
	if err != nil {
		return purgeScope{}, err
	}
	configDigest, err := documentDigest(i.Manifest.Config)
	if err != nil {
		return purgeScope{}, err
	}
	pinnedCode, err := i.retiredCode(p.Backups)
	if err != nil {
		return purgeScope{}, err
	}
	sets := make(map[string]bool)
	knownVolume := make(map[string]store.Volume, len(p.Volumes))
	knownImage := make(map[string]map[string]bool)
	knownBackup := make(map[string]bool, len(p.Backups))
	for _, v := range p.Volumes {
		if !ownedVolume(v) {
			return purgeScope{}, store.ErrApprovalMismatch
		}
		knownVolume[filepath.Base(v.Path)] = v
	}
	for _, img := range p.Images {
		if !ownedImage(img) || (img.State != store.Prepared && img.State != store.Published) {
			return purgeScope{}, store.ErrCleanupPending
		}
		if knownImage[img.EpochID] == nil {
			knownImage[img.EpochID] = make(map[string]bool)
		}
		knownImage[img.EpochID][img.ID] = true
		sets[draftName(img.ID)] = true
		sets[".writing-"+draftName(img.ID)] = true
	}
	for _, b := range p.Backups {
		knownBackup[b.ID] = true
	}
	for _, name := range pinnedCode {
		sets[name] = true
	}
	for _, name := range []string{i.Manifest.CodeDir, "volumes", "images", "backups", "preparations", "instances", "ipc", "app", ".writing-" + pendingName, ".writing-" + manifestName} {
		sets[name] = true
	}
	audit, err := i.collectPurgeRestoreAudit(ctx, db)
	if err != nil {
		return purgeScope{}, err
	}
	for _, m := range audit {
		sets[m.Path] = true
	}
	names, err := maintenanceNames(i.Root)
	if err != nil {
		return purgeScope{}, err
	}
	rootID, err := maintenanceDirectoryIdentity(i.Root, ".")
	if err != nil {
		return purgeScope{}, err
	}
	purg := purgeScope{Format: Format, Root: i.Path, RootNativeID: rootID, ParentRetained: filepath.Dir(i.Path), Owner: i.Manifest.Owner, ConfigDigest: configDigest, ManifestDigest: hashBytes(manifest), Ledger: p,
		Finalize: []string{store.DatabaseName, manifestName, ownerLock, purgeIntent, ".writing-" + purgeIntent, "."}, TerminalReceipt: purgeTerminalName(i.Path)}
	purg.RestoreAudit = audit
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return purgeScope{}, err
		}
		switch name {
		case store.DatabaseName, manifestName, ownerLock, purgeIntent, ".writing-" + purgeIntent:
			continue
		}
		if !sets[name] {
			return purgeScope{}, fmt.Errorf("refusing unknown path in portable installation: %q", name)
		}
		purg.Remove = append(purg.Remove, name)
	}
	sort.Strings(purg.Remove)
	for _, ns := range []struct {
		name  string
		allow func(string) bool
	}{{"volumes", func(s string) bool { return knownVolume[s].ID != "" }},
		{"images", func(s string) bool { return generationPattern.MatchString(s) }},
		{"backups", func(s string) bool { return knownBackup[s] }},
		{"instances", func(string) bool { return false }},
		{"preparations", func(string) bool { return false }},
		{"ipc", func(string) bool { return false }},
		{"app", func(s string) bool {
			return s == "uploads" || s == "discord" || s == discordTokenLeaf || s == ".writing-"+discordTokenLeaf
		}},
		{"app/uploads", func(s string) bool {
			return s == ".owner" || strings.HasPrefix(s, "file-") && generationPattern.MatchString(strings.TrimPrefix(s, "file-"))
		}},
		{"app/discord", func(s string) bool { return s == discordOwnershipLeaf || s == discordOwnershipLeaf+"-journal" }},
	} {
		if err := checkPurgeNamespace(i.Root, ns.name, ns.allow); err != nil {
			return purgeScope{}, err
		}
	}
	images, err := maintenanceDirectoryAt(i.Root, "images", false)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return purgeScope{}, err
	}
	if err == nil {
		names, err := maintenanceNames(images)
		if err := errors.Join(err, images.Close()); err != nil {
			return purgeScope{}, err
		}
		for _, id := range names {
			if err := checkPurgeNamespace(i.Root, "images/"+id, func(s string) bool { return knownImage[id][s] }); err != nil {
				return purgeScope{}, err
			}
		}
	}
	for _, name := range purg.Remove {
		if err := collectPurgeEntries(i.Root, name, "", &purg.Entries); err != nil {
			return purgeScope{}, err
		}
	}
	return purg, nil
}

func checkPurgeNamespace(root *os.Root, name string, allow func(string) bool) error {
	d, err := maintenanceDirectoryAt(root, name, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	names, err := maintenanceNames(d)
	if err := errors.Join(err, d.Close()); err != nil {
		return err
	}
	for _, leaf := range names {
		if !allow(leaf) {
			return fmt.Errorf("refusing unknown path in deletion namespace: %s/%s", name, leaf)
		}
	}
	return nil
}

func (p purgeScope) checkManifest(root *os.Root, m Manifest) error {
	manifest, err := readDocument(root, manifestName)
	if err != nil {
		return err
	}
	config, err := documentDigest(m.Config)
	if err != nil {
		return err
	}
	if p.Owner != m.Owner || p.Ledger.InstallationIdentity != identity(m) || p.ManifestDigest != hashBytes(manifest) || p.ConfigDigest != config {
		return store.ErrApprovalMismatch
	}
	return nil
}

func (i *Installation) validatePurge(ctx context.Context, p purgeScope, recovering bool) error {
	for _, m := range p.RestoreAudit {
		if m.Path != restoreReceiptName && m.Path != backupConfigName || m.Size < 0 || m.Size > maxDocument || !digestPattern.MatchString(m.Digest) {
			return store.ErrApprovalMismatch
		}
		f, err := maintenanceOpen(i.Root, m.Path)
		if recovering && errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if err := errors.Join(verifyMaintenanceFile(ctx, f, m.Size, m.Digest, 0), f.Close()); err != nil {
			return err
		}
	}
	for _, v := range p.Ledger.Volumes {
		if !ownedVolume(v) {
			return store.ErrApprovalMismatch
		}
		if recovering {
			if err := absent(i.Root, v.Path); err == nil {
				continue // This frozen generation may already have been removed.
			}
		}
		if _, err := sandbox.ObserveVolume(i.Root, v); err != nil {
			return err
		}
	}
	var actual []purgeEntry
	for _, name := range p.Remove {
		if err := collectPurgeEntries(i.Root, name, "", &actual); err != nil {
			return err
		}
	}
	if !recovering && !reflect.DeepEqual(actual, p.Entries) {
		return store.ErrApprovalMismatch
	}
	expected := make(map[string]string, len(p.Entries))
	for _, e := range p.Entries {
		expected[e.Path] = e.NativeID
	}
	for _, e := range actual {
		if expected[e.Path] != e.NativeID {
			return fmt.Errorf("%w: purge path changed: %s", store.ErrApprovalMismatch, e.Path)
		}
	}
	return nil
}

func (i *Installation) collectPurgeRestoreAudit(ctx context.Context, db *store.Store) ([]backupMember, error) {
	digest, err := db.RestoredReceiptDigest(ctx)
	if err != nil || digest == "" {
		return nil, err
	}
	raw, err := readDocument(i.Root, restoreReceiptName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil || hashBytes(raw) != digest {
		return nil, errors.Join(store.ErrApprovalMismatch, err)
	}
	members, err := restoreInventory(raw)
	if err != nil {
		return nil, err
	}
	// validatePurge hashes both members before and after confirmation. The
	// detached config is identified only by the ledger-bound receipt.
	return []backupMember{{Path: restoreReceiptName, Size: int64(len(raw)), Digest: digest}, members[backupConfigName]}, nil
}

func collectPurgeEntries(root *os.Root, leaf, prefix string, entries *[]purgeEntry) error {
	if !maintenanceLeaf(leaf) {
		return store.ErrApprovalMismatch
	}
	info, err := root.Lstat(leaf)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	name := prefix + leaf
	if info.IsDir() {
		dir, err := maintenanceDir(root, leaf)
		if err != nil {
			return err
		}
		defer dir.Close()
		f, err := dir.Open(".")
		if err != nil {
			return err
		}
		id, err := maintenanceHandleIdentity(f)
		if err := errors.Join(err, f.Close()); err != nil {
			return err
		}
		*entries = append(*entries, purgeEntry{name, id})
		names, err := maintenanceNames(dir)
		if err != nil {
			return err
		}
		sort.Strings(names)
		for _, sub := range names {
			if err := collectPurgeEntries(dir, sub, name+"/", entries); err != nil {
				return err
			}
		}
		return nil
	}
	f, err := maintenanceOpen(root, leaf)
	if err != nil {
		return err
	}
	id, err := maintenanceHandleIdentity(f)
	if err := errors.Join(err, f.Close()); err != nil {
		return err
	}
	*entries = append(*entries, purgeEntry{name, id})
	return nil
}

func readPurgeScope(root *os.Root, name, path string) (purgeScope, error) {
	var p purgeScope
	raw, err := readDocument(root, name)
	if err != nil {
		return p, err
	}
	if err := gvxcontract.DecodeStrict(raw, maxDocument, 128, &p); err != nil {
		return p, err
	}
	owner, err := process.OwnerIdentity()
	if err != nil {
		return p, err
	}
	if p.Format != Format || p.Root != path || p.ParentRetained != filepath.Dir(path) || p.Owner != owner || p.Ledger.Owner != owner || !generationPattern.MatchString(p.Ledger.ID) || !digestPattern.MatchString(p.Ledger.Digest) || p.RootNativeID == "" || p.TerminalReceipt != purgeTerminalName(path) {
		return p, store.ErrApprovalMismatch
	}
	return p, nil
}

func checkPurgeReceipt(ctx context.Context, parent *os.Root, path string, confirm Confirm) (bool, error) {
	p, err := readPurgeScope(parent, purgeTerminalName(path), path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	// The final receipt is only created after CompletePurge and Store.Close.
	if err := approvePurge(ctx, p, confirm); err != nil {
		return true, err
	}
	root, err := maintenanceDir(parent, filepath.Base(path))
	if errors.Is(err, fs.ErrNotExist) {
		return true, removeMaintenanceFile(parent, purgeTerminalName(path))
	}
	if err != nil {
		return true, err
	}
	defer root.Close()
	if q, err := readPurgeScope(root, purgeIntent, path); err == nil {
		if !reflect.DeepEqual(p, q) {
			return true, store.ErrApprovalMismatch
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return true, err
	}
	return true, finishNativePurge(parent, root, path, p)
}

func (p purgeScope) checkRoot(parent, root *os.Root, path string) error {
	rootID, err := maintenanceDirectoryIdentity(root, ".")
	if err != nil || rootID != p.RootNativeID {
		return errors.Join(store.ErrApprovalMismatch, err)
	}
	currentID, err := maintenanceDirectoryIdentity(parent, filepath.Base(path))
	if err != nil || currentID != rootID {
		return errors.Join(store.ErrApprovalMismatch, err)
	}
	return nil
}

func finishNativePurge(parent, root *os.Root, path string, p purgeScope) error {
	if err := p.checkRoot(parent, root, path); err != nil {
		return err
	}
	names, err := maintenanceNames(root)
	if err != nil {
		return err
	}
	for _, name := range names {
		switch name {
		case store.DatabaseName, manifestName, ownerLock, purgeIntent, ".writing-" + purgeIntent:
			if err := checkMaintenanceFile(root, name); err != nil {
				return err
			}
		default:
			return fmt.Errorf("refusing to finalize purge with unremoved path %q", name)
		}
	}
	if err := verifyPurgeLedger(root, path, p); err != nil {
		return err
	}
	if raw, err := readDocument(root, manifestName); err == nil {
		if hashBytes(raw) != p.ManifestDigest {
			return store.ErrApprovalMismatch
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// No code/data tree remains. The parent lock protects the exact root
	// identity until we have removed its per-installation lock and root.
	for _, name := range []string{store.DatabaseName, manifestName, ownerLock, purgeIntent, ".writing-" + purgeIntent} {
		if err := removeMaintenanceFile(root, name); err != nil {
			return errors.Join(store.ErrCleanupPending, err)
		}
	}
	if err := root.Close(); err != nil {
		return err
	}
	if err := parent.Remove(filepath.Base(path)); err != nil {
		return err
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}
	return removeMaintenanceFile(parent, purgeTerminalName(path))
}

func verifyPurgeLedger(root *os.Root, path string, p purgeScope) error {
	if err := absent(root, store.DatabaseName); err == nil {
		return nil
	}
	db, err := store.Open(context.Background(), path, p.Ledger.InstallationIdentity)
	if err != nil {
		return err
	}
	r, err := db.Installation(context.Background())
	if err := errors.Join(err, db.Close()); err != nil {
		return err
	}
	if r.State != store.Purged || r.PurgeDigest != p.Ledger.Digest {
		return store.ErrApprovalMismatch
	}
	return nil
}

func checkMaintenanceFile(root *os.Root, name string) error {
	f, err := maintenanceOpen(root, name)
	if err != nil {
		return err
	}
	return f.Close()
}

func removeMaintenanceFile(root *os.Root, name string) error {
	f, err := maintenanceOpen(root, name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err == nil {
		err = allowMaintenanceUnlink(f, info)
	}
	if err := errors.Join(err, f.Close()); err != nil {
		return err
	}
	if err := root.Remove(name); err != nil {
		return err
	}
	return syncDirectory(root)
}
