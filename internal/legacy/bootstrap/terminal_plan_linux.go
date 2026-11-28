//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/legacy/host"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"sort"
)

func purgeRecordPath(record host.ProvisionRecord) (string, error) {
	if record.Kind == "account" {
		return "", nil
	}
	if record.Kind == "bundle" {
		var p host.ProvisionProperties
		if e := gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
			return "", e
		}
		return p.Path, nil
	}
	if filepath.IsAbs(record.Identity) {
		return record.Identity, nil
	}
	return "", nil
}
func selectedDeletionCovers(roots map[string]bool, path string) bool {
	return roots[path]
}

func purgeMountedStorage(records []host.ProvisionRecord, m host.InstallationManifest, backingSelected bool) (bool, error) {
	if !backingSelected || m.Backing.Dev == 0 || m.Backing.Ino == 0 || m.Backing.XFSUUID == "" {
		return false, nil
	}
	var backing unix.Stat_t
	if e := unix.Lstat(m.Paths.BackingFile, &backing); os.IsNotExist(e) {
		return false, nil
	} else if e != nil {
		return false, e
	}
	if backing.Mode&unix.S_IFMT != unix.S_IFREG || uint64(backing.Dev) != m.Backing.Dev || backing.Ino != m.Backing.Ino || backing.Size != m.Backing.SizeBytes {
		return false, nil
	}
	native, e := terminalObserve(m.Paths.StorageRoot)
	if e != nil {
		return false, e
	}
	for _, record := range records {
		if record.Kind != "directory" || record.Identity != m.Paths.StorageRoot || record.State != "OBSERVED" {
			continue
		}
		var p host.ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
			return false, e
		}
		if p.Volume != nil && *p.Volume == m.Backing && p.Path == m.Paths.StorageRoot && native.Kind == "directory" && native.Device == p.Dev && native.Inode == p.Ino {
			return true, nil
		}
	}
	return false, nil
}

func purgeDirectoryClosed(path string, roots map[string]bool, m host.InstallationManifest, records []host.ProvisionRecord, mountedStorage bool) (bool, error) {
	if path == m.Paths.StorageRoot && mountedStorage {
		return true, nil
	}
	entries, e := os.ReadDir(path)
	if os.IsNotExist(e) {
		return true, nil
	}
	if e != nil {
		return false, e
	}
	for _, entry := range entries {
		child := filepath.Join(path, entry.Name())
		if selectedDeletionCovers(roots, child) {
			continue
		}
		metadata := false
		if path == m.Paths.Control {
			for _, name := range terminalControlNames {
				metadata = metadata || name == entry.Name()
			}
			if entry.Name() == ".purge-helper" {
				for _, record := range records {
					if record.Kind != "directory" || record.Identity != child || record.State != "OBSERVED" || !record.ProductCreated || record.ExistedBefore || record.CleanupState == "COMPLETE" {
						continue
					}
					var p host.ProvisionProperties
					if e = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &p); e != nil {
						return false, e
					}
					metadata = p.Source == purgeHelperSource && p.Digest == m.BundleDigest
				}
			}
		}
		if !metadata {
			return false, nil
		}
	}
	return true, nil
}

func ownedPurgeClosure(records []host.ProvisionRecord, m host.InstallationManifest) ([]host.ProvisionRecord, error) {
	var payload, directories []host.ProvisionRecord
	roots := map[string]bool{}
	backingSelected := false
	for _, record := range records {
		if !record.ProductCreated || record.ExistedBefore || record.CleanupState == "COMPLETE" || sharedNetworkObject(record.Kind, record.Identity) || insideStorage(record, m) || record.Kind == "loop" || record.Kind == "mount" {
			continue
		}
		if record.State != "OBSERVED" {
			return nil, errors.New("purge requires reconciled observed ownership")
		}
		if record.Kind == "unit" {
			var p host.ProvisionProperties
			if e := gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
				return nil, e
			}
			if p.Path == "" {
				continue
			}
		}
		if record.Kind == "directory" {
			directories = append(directories, record)
			continue
		}
		path, e := purgeRecordPath(record)
		if e != nil {
			return nil, e
		}
		if path != "" {
			roots[path] = true
		}
		backingSelected = backingSelected || record.Kind == "backing" && path == m.Paths.BackingFile
		payload = append(payload, record)
	}
	mounted, e := purgeMountedStorage(records, m, backingSelected)
	if e != nil {
		return nil, e
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i].Identity) > len(directories[j].Identity) })
	chosen := map[string]bool{}
	preserveEvidence := false
	for _, directory := range directories {
		closed, e := purgeDirectoryClosed(directory.Identity, roots, m, records, mounted)
		if e != nil {
			return nil, e
		}
		if closed {
			roots[directory.Identity] = true
			chosen[directory.ID] = true
		} else if directory.Identity != m.Paths.Control && !isAncestor(directory.Identity, m.Paths.Control) {
			preserveEvidence = true
		}
	}
	if preserveEvidence {
		delete(roots, m.Paths.Control)
		for _, directory := range directories {
			if !chosen[directory.ID] {
				continue
			}
			closed := directory.Identity != m.Paths.Control
			if closed {
				closed, e = purgeDirectoryClosed(directory.Identity, roots, m, records, mounted)
				if e != nil {
					return nil, e
				}
			}
			if !closed {
				delete(chosen, directory.ID)
				delete(roots, directory.Identity)
			}
		}
	}
	for _, directory := range directories {
		if chosen[directory.ID] {
			payload = append(payload, directory)
		}
	}
	return payload, nil
}

func validateExactPurgeClosure(records []host.ProvisionRecord, m host.InstallationManifest, scope []ApprovedObject) error {
	chosen := map[string]bool{}
	backingSelected := false
	for _, approval := range scope {
		chosen[approval.Kind+":"+approval.Identity] = true
		backingSelected = backingSelected || approval.Kind == "backing" && approval.Identity == m.Paths.BackingFile
	}
	roots := map[string]bool{}
	var directories []host.ProvisionRecord
	for _, record := range records {
		if !chosen[record.Kind+":"+record.Identity] {
			continue
		}
		if sharedNetworkObject(record.Kind, record.Identity) {
			return errors.New("shared management/network anchors cannot enter purge deletion scope")
		}
		if insideStorage(record, m) {
			continue
		}
		if record.Kind == "directory" {
			directories = append(directories, record)
			continue
		}
		path, e := purgeRecordPath(record)
		if e != nil {
			return e
		}
		if path != "" {
			roots[path] = true
		}
	}
	mounted, e := purgeMountedStorage(records, m, backingSelected)
	if e != nil {
		return e
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i].Identity) > len(directories[j].Identity) })
	for _, directory := range directories {
		closed, e := purgeDirectoryClosed(directory.Identity, roots, m, records, mounted)
		if e != nil {
			return e
		}
		if !closed {
			return errors.New("purge selected a directory with a foreign or unselected direct child")
		}
		roots[directory.Identity] = true
	}
	return nil
}

func preflightTerminalControl(ctx context.Context, store *host.Store, m host.InstallationManifest, approval PurgeApproval, records []host.ProvisionRecord) error {
	selected := false
	for _, object := range approval.Scope {
		selected = selected || object.Kind == "directory" && object.Identity == m.Paths.Control
	}
	if !selected {
		return nil
	}
	allowed := map[string]bool{}
	for _, name := range terminalControlNames {
		allowed[name] = true
	}
	private := filepath.Join(m.Paths.Control, ".purge-helper")
	for _, record := range records {
		if record.Kind != "directory" || record.Identity != private || record.State != "OBSERVED" || !record.ProductCreated || record.ExistedBefore || record.CleanupState == "COMPLETE" {
			continue
		}
		owned, e := purgeHelperArtifact(ctx, store, m, record)
		if e != nil {
			return e
		}
		if owned {
			if e = matchPurgeRecord(ctx, store, record); e != nil {
				return e
			}
			allowed[".purge-helper"] = true
		}
	}
	entries, e := os.ReadDir(m.Paths.Control)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return errors.New("terminal control contains an unknown child before payload deletion")
		}
	}
	return nil
}

func preflightPurgeEvidence(ctx context.Context, store *host.Store, m host.InstallationManifest, approval PurgeApproval, records []host.ProvisionRecord) error {
	selected := map[string]bool{}
	for _, object := range approval.Scope {
		selected[object.Kind+":"+object.Identity] = true
	}
	if !selected["directory:"+m.Paths.Control] {
		return nil
	}
	for _, record := range records {
		if !record.ProductCreated || record.ExistedBefore || record.CleanupState == "COMPLETE" || sharedNetworkObject(record.Kind, record.Identity) || insideStorage(record, m) || record.Kind == "loop" || record.Kind == "mount" || selected[record.Kind+":"+record.Identity] || record.Kind == "directory" && isAncestor(record.Identity, m.Paths.Control) {
			continue
		}
		helper, e := purgeHelperArtifact(ctx, store, m, record)
		if e != nil {
			return e
		}
		if helper {
			continue
		}
		if record.Kind == "unit" {
			var p host.ProvisionProperties
			if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
				return e
			}
			if p.Path == "" {
				continue
			}
		}
		return errors.New("purge cannot erase control evidence while an installation-owned object is unselected")
	}
	return nil
}
