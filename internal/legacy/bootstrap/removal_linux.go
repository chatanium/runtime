//go:build linux

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	legacyhost "github.com/thirdscam/chatanium/internal/legacy/host"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func serviceName(id RuntimeInstallationID) string { return legacyhost.ManagerUnitName(string(id)) }
func servicePath(id RuntimeInstallationID) string {
	return filepath.Join("/etc/systemd/system", serviceName(id))
}
func maintenance(ctx context.Context, id RuntimeInstallationID) (*ownedSession, error) {
	return openOwner(ctx, id, Foreground)
}
func closeMaintenance(s *ownedSession) error {
	if s == nil {
		return nil
	}
	var result error
	if s.networkCancel != nil {
		s.networkCancel()
	}
	if s.network != nil {
		result = errors.Join(result, s.network.Close())
	}
	if s.supervisor != nil {
		result = errors.Join(result, s.supervisor.Close())
	}
	if s.storage != nil {
		result = errors.Join(result, s.storage.Close())
	}
	return errors.Join(result, s.systemd.Close(), s.lease.Close(), s.store.Close())
}
func unitText(m legacyhost.InstallationManifest) ([]byte, error) {
	if strings.ContainsAny(m.Paths.Launcher, "\n\r\x00%\"\\") || strings.ContainsAny(m.RuntimeInstallationID, "\n\r\x00%\"\\") {
		return nil, errors.New("unsafe service path")
	}
	return []byte(fmt.Sprintf("[Unit]\nDescription=Chatanium runtime %s\nAfter=local-fs.target network-online.target\n[Service]\nType=simple\nWorkingDirectory=/\nExecStart=\"%s\" _owner --installation-id %s\nRestart=on-failure\nKillMode=control-group\nTimeoutStopSec=120\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n", m.RuntimeInstallationID, m.Paths.Launcher, m.RuntimeInstallationID)), nil
}
func ownedRecord(ctx context.Context, s *legacyhost.Store, kind, identity string) (legacyhost.ProvisionRecord, error) {
	records, e := s.PendingProvisions(ctx)
	if e != nil {
		return legacyhost.ProvisionRecord{}, e
	}
	for _, r := range records {
		if r.Kind == kind && r.Identity == identity && r.ProductCreated && r.State == "OBSERVED" {
			return r, nil
		}
	}
	return legacyhost.ProvisionRecord{}, errors.New("object is not ledger-owned")
}
func matchRecord(r legacyhost.ProvisionRecord) error {
	var p legacyhost.ProvisionProperties
	if e := gvxcontract.DecodeStrict(r.Observed.Attributes, 64<<10, 16, &p); e != nil {
		return e
	}
	if r.Kind == "account" {
		if p.Source == "group" {
			return validateGroupOnly(p)
		}
		return validateAccount(legacyhost.NumericIdentity{Name: p.Name, UID: p.UID, GID: p.GID, ProductCreated: r.ProductCreated})
	}
	path := r.Identity
	if r.Kind == "bundle" {
		path = p.Path
	}
	if e := trustedPath(path, false); e != nil {
		return e
	}
	var st unix.Stat_t
	if e := unix.Lstat(path, &st); e != nil {
		return e
	}
	if p.Dev != 0 && (uint64(st.Dev) != p.Dev || st.Ino != p.Ino) || p.Mode != 0 && st.Mode&07777 != p.Mode || p.SizeBytes != 0 && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Size != p.SizeBytes {
		return errors.New("ledger object kernel identity mismatch")
	}
	if p.Digest != "" && st.Mode&unix.S_IFMT == unix.S_IFREG {
		fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if e != nil {
			return e
		}
		f := os.NewFile(uintptr(fd), path)
		actual, e := streamDigest(f)
		f.Close()
		if e != nil {
			return e
		}
		if actual != p.Digest {
			return errors.New("owned file digest mismatch")
		}
	}
	return nil
}
func removeRecorded(ctx context.Context, s *ownedSession, r legacyhost.ProvisionRecord, evidence legacyhost.CleanupEvidence) error {
	if !removableProductObject(r) {
		return errors.New("removal cannot consume borrowed, preexisting, or unobserved object ownership")
	}
	if complete, e := rejectCompletedReappearance(ctx, s.store, r); complete || e != nil {
		return e
	}
	if absent, e := bootEphemeralAbsent(ctx, s.store, r); e != nil {
		return e
	} else if absent {
		removal, e := beginRemoval(ctx, s.store, r)
		if e != nil {
			return e
		}
		return errors.Join(s.store.CompleteProvisionCleanup(ctx, r.ID, evidence), s.store.CompleteProvisionCleanup(ctx, removal, evidence))
	}
	if e := matchPurgeRecord(ctx, s.store, r); e != nil {
		return e
	}
	removal, e := beginRemoval(ctx, s.store, r)
	if e != nil {
		return e
	}
	if r.Kind == "account" {
		if e = removeAccount(ctx, s, r); e != nil {
			return e
		}
		evidence, e = s.systemd.SettleHelpers(ctx)
		if e != nil {
			return e
		}
	} else {
		if e = os.Remove(r.Identity); e != nil && !os.IsNotExist(e) {
			return e
		}
		parent, e := os.Open(filepath.Dir(r.Identity))
		if e != nil {
			return e
		}
		e = parent.Sync()
		if e == nil && r.Kind == "backing" {
			e = unix.Syncfs(int(parent.Fd()))
		}
		parent.Close()
		if e != nil {
			return e
		}
	}
	if s.purgeRetirements[r.ID] {
		return nil
	}
	return errors.Join(s.store.CompleteProvisionCleanup(ctx, r.ID, evidence), s.store.CompleteProvisionCleanup(ctx, removal, evidence))
}
func Uninstall(ctx context.Context, id RuntimeInstallationID) (RemovalResult, error) {
	r := RemovalResult{InstallationID: id}
	cleanup, e := Stop(ctx, id)
	if e != nil || !cleanup.Complete {
		return r, errors.Join(e, host.ErrCleanupIncomplete)
	}
	s, e := cleanupLocked(ctx, id)
	if e != nil {
		return r, e
	}
	defer closeMaintenance(s)
	if e = s.store.AssertRemovable(ctx); e != nil {
		return r, e
	}
	records, e := s.store.PendingProvisions(ctx)
	if e != nil {
		return r, e
	}
	for _, object := range records {
		if uninstallRemovable(object, s.manifest) {
			if object.Kind == "unit" {
				if e = stopOwnedManager(ctx, s); e != nil {
					return r, e
				}
				if e = s.systemd.DisableUnit(ctx, serviceName(id)); e != nil {
					return r, e
				}
			}
			if e = removeRecorded(ctx, s, object, s.cleanupEvidence); e != nil {
				r.Pending = append(r.Pending, ObjectResult{Kind: object.Kind, Identity: object.Identity, State: "pending"})
				return r, e
			}
			r.Removed = append(r.Removed, ObjectResult{Kind: object.Kind, Identity: object.Identity, State: "removed"})
		} else {
			r.Preserved = append(r.Preserved, ObjectResult{Kind: object.Kind, Identity: object.Identity, State: "preserved"})
		}
	}
	return r, s.systemd.Reload(ctx)
}
func Purge(ctx context.Context, id RuntimeInstallationID, a PurgeApproval) (RemovalResult, error) {
	r := RemovalResult{InstallationID: id}
	if a.InstallationID != id || !validID(a.PlanID) {
		return r, errors.New("purge identity mismatch")
	}
	sum, e := PurgePlanDigest(a)
	if e != nil || sum != a.PlanDigest {
		return r, errors.New("purge approval digest mismatch")
	}
	if e = validateObjects(a.Scope, true); e != nil {
		return r, e
	}
	if e = rootRequired(); e != nil {
		return r, e
	}
	if e = validateTerminalPlacement(a); e != nil {
		return r, e
	}
	originalApproval := a
	baseCtx := ctx
	guard, e := legacyhost.AcquireManagementGuard(ctx, legacyhost.ManagementExclusive)
	if e != nil {
		return r, e
	}
	defer func() {
		if guard != nil {
			guard.Close()
		}
	}()
	ctx = legacyhost.WithManagementGuard(baseCtx, guard)
	if e = verifyApprovedManagementAnchor(ctx, a.ManagementAnchor); e != nil {
		return r, e
	}
	if result, terminal, err := terminalResumeSource(ctx, guard, id, a); terminal || err != nil {
		return result, err
	}
	saved, pending, e := terminalApprovedPlan(ctx, guard, id)
	if e != nil {
		return r, e
	}
	if pending && saved.PlanDigest != a.PlanDigest {
		return r, errors.New("pending purge requires its original full approval")
	}
	if !pending {
		if e = guard.Close(); e != nil {
			return r, e
		}
		guard = nil
		response, live, err := contactOwner(baseCtx, id, managementRequest{Operation: "stop"}, nil)
		if live && (response.Report == nil || !response.Report.Complete) {
			return r, errors.Join(err, host.ErrCleanupIncomplete)
		}
		if !live && err != nil {
			return r, err
		}
		if live {
			if e = waitOwnerRelease(baseCtx, id); e != nil {
				return r, e
			}
		}
		guard, e = legacyhost.AcquireManagementGuard(baseCtx, legacyhost.ManagementExclusive)
		if e != nil {
			return r, e
		}
		ctx = legacyhost.WithManagementGuard(baseCtx, guard)
		if e = verifyApprovedManagementAnchor(ctx, a.ManagementAnchor); e != nil {
			return r, e
		}
		if result, terminal, err := terminalResumeSource(ctx, guard, id, a); terminal || err != nil {
			return result, err
		}
	}
	admission := &terminalAdmission{approval: originalApproval, guard: guard}
	ctx = context.WithValue(ctx, terminalAdmissionKey{}, admission)
	if e = preflightCompletedScope(ctx, id, a.Scope); e != nil {
		return r, e
	}
	if e = preflightRetiredRuntime(ctx, id); e != nil {
		return r, e
	}
	coordination, e := lockDevelopmentForPurge(ctx, id)
	if e != nil {
		return r, e
	}
	if coordination != nil {
		defer coordination.Close()
	}
	s, removed, remaining, e := acquirePurgeSession(ctx, id, a.Scope)
	r.Removed = append(r.Removed, removed...)
	if e != nil {
		return r, e
	}
	a.Scope = remaining
	defer func() {
		if s != nil {
			closeMaintenance(s)
		}
	}()
	if s.manifest.ActiveRevision != a.ExpectedActiveRevision || s.manifest.DesiredRunState != "STOPPED" {
		return r, errors.New("purge revision or intent changed")
	}
	if e = s.store.AssertRemovable(ctx); e != nil {
		return r, e
	}
	records, e := purgeRecords(ctx, s.store, a.Scope)
	if e != nil {
		return r, e
	}
	scope := map[string]ApprovedObject{}
	for _, object := range a.Scope {
		scope[object.Kind+":"+object.Identity] = object
	}
	_, removeBacking := scope["backing:"+s.manifest.Paths.BackingFile]
	selected, contained := []legacyhost.ProvisionRecord{}, []legacyhost.ProvisionRecord{}
	removeControl := false
	preservedOwned := false
	var helperArtifacts []legacyhost.ProvisionRecord
	for _, record := range records {
		if helper, lookup := purgeHelperArtifact(ctx, s.store, s.manifest, record); lookup != nil {
			return r, lookup
		} else if helper {
			helperArtifacts = append(helperArtifacts, record)
			continue
		}
		if sharedNetworkObject(record.Kind, record.Identity) {
			r.Preserved = append(r.Preserved, ObjectResult{Kind: record.Kind, Identity: record.Identity, State: "preserved"})
			delete(scope, record.Kind+":"+record.Identity)
			continue
		}
		if record.Kind == "loop" || record.Kind == "mount" {
			if e = s.store.CompleteProvisionCleanup(ctx, record.ID, s.cleanupEvidence); e != nil {
				return r, e
			}
			delete(scope, record.Kind+":"+record.Identity)
			continue
		}
		if insideStorage(record, s.manifest) {
			if removeBacking {
				if approval, ok := scope[record.Kind+":"+record.Identity]; ok {
					if e = authorizePurgeRecord(ctx, s.store, record, approval); e != nil {
						return r, e
					}
					delete(scope, record.Kind+":"+record.Identity)
				}
				contained = append(contained, record)
			} else {
				r.Preserved = append(r.Preserved, ObjectResult{Kind: record.Kind, Identity: record.Identity, State: "preserved"})
				preservedOwned = preservedOwned || record.ProductCreated
			}
			continue
		}
		approval, ok := scope[record.Kind+":"+record.Identity]
		if !ok {
			r.Preserved = append(r.Preserved, ObjectResult{Kind: record.Kind, Identity: record.Identity, State: "preserved"})
			preservedOwned = preservedOwned || (record.ProductCreated && !record.ExistedBefore && !(record.Kind == "directory" && isAncestor(record.Identity, s.manifest.Paths.Control)))
			continue
		}
		if e = authorizePurgeRecord(ctx, s.store, record, approval); e != nil {
			return r, e
		}
		if e = matchPurgeRecord(ctx, s.store, record); e != nil {
			return r, e
		}
		selected = append(selected, record)
		delete(scope, record.Kind+":"+record.Identity)
		removeControl = removeControl || record.Identity == s.manifest.Paths.Control
	}
	if len(scope) != 0 {
		return r, errors.New("purge scope includes objects without proven ownership")
	}
	if removeControl && preservedOwned {
		return r, errors.New("ownership evidence must remain while installation-owned objects are preserved")
	}
	retirements, e := releasePurgeReferences(ctx, s, selected, removeBacking)
	if e != nil {
		return r, e
	}
	sort.SliceStable(selected, func(i, j int) bool { return purgeOrder(selected[i], s.manifest) < purgeOrder(selected[j], s.manifest) })
	var ancestors []legacyhost.ProvisionRecord
	for _, record := range selected {
		if record.Identity == s.manifest.Paths.Control {
			continue
		}
		if record.Kind == "directory" && isAncestor(record.Identity, s.manifest.Paths.Control) {
			ancestors = append(ancestors, record)
			continue
		}
		if record.Kind == "bundle" {
			e = removeBundle(ctx, s, record, s.cleanupEvidence)
		} else {
			if record.Kind == "unit" && record.Identity == servicePath(id) && record.CleanupState != "COMPLETE" {
				if e = stopOwnedManager(ctx, s); e != nil {
					return r, e
				}
				if e = s.systemd.DisableUnit(ctx, serviceName(id)); e != nil {
					return r, e
				}
				if e = s.systemd.Reload(ctx); e != nil {
					return r, e
				}
			}
			e = removeRecorded(ctx, s, record, s.cleanupEvidence)
		}
		if e != nil {
			r.Pending = append(r.Pending, ObjectResult{Kind: record.Kind, Identity: record.Identity, State: "pending"})
			return r, e
		}
		if record.Kind == "backing" && record.Identity == s.manifest.Paths.BackingFile {
			for _, child := range contained {
				if e = s.store.CompleteProvisionCleanup(ctx, child.ID, s.cleanupEvidence); e != nil {
					return r, e
				}
				r.Removed = append(r.Removed, ObjectResult{Kind: child.Kind, Identity: child.Identity, State: "removed"})
			}
		}
		r.Removed = append(r.Removed, ObjectResult{Kind: record.Kind, Identity: record.Identity, State: "removed"})
	}
	if e = removePurgeHelpers(ctx, s, helperArtifacts); e != nil {
		return r, e
	}
	if e = completePurgeRetirement(ctx, s, retirements, removeBacking); e != nil {
		return r, e
	}
	if removeControl {
		if e = validateControlAncestors(s.manifest.Paths.Control, ancestors); e != nil {
			return r, e
		}
	}
	if removeControl {
		if !admission.ready {
			return r, errors.New("terminal publication capability was not proven before payload removal")
		}
		targets, err := terminalCaptureTargets(s.manifest, ancestors)
		if err != nil {
			return r, err
		}
		guards, err := terminalCaptureGuards(ctx, s.store, s.manifest, originalApproval, helperArtifacts, targets)
		if err != nil {
			return r, err
		}
		approvalRaw, err := json.Marshal(originalApproval)
		if err != nil {
			return r, err
		}
		fence, err := s.store.PrepareTerminalPurge(ctx, guard, admission.capability, approvalRaw, originalApproval.PlanID, s.cleanupEvidence, targets, guards)
		if err != nil {
			return r, err
		}
		receipt, err := terminalPublishFenced(ctx, guard, s.store, fence, originalApproval)
		if err != nil {
			return r, err
		}
		if err = closeMaintenance(s); err != nil {
			return r, err
		}
		s = nil
		terminalResult, err := terminalFinish(ctx, guard, receipt)
		r.Removed = append(r.Removed, terminalResult.Removed...)
		r.Preserved = append(r.Preserved, terminalResult.Preserved...)
		r.Pending = append(r.Pending, terminalResult.Pending...)
		return r, err
	}
	if e = preflightCompletedScope(ctx, id, originalApproval.Scope); e != nil {
		return r, e
	}
	if e = s.store.RetireTerminalPublicationProbe(ctx, guard, admission.capability); e != nil {
		return r, e
	}
	return r, nil
}
func purgeOrder(r legacyhost.ProvisionRecord, m legacyhost.InstallationManifest) int {
	if r.Identity == m.Paths.Control {
		return 100000
	}
	if r.Kind == "bundle" {
		return 90000
	}
	if r.Identity == m.Paths.EngineRoot {
		return 95000
	}
	if r.Kind == "account" {
		return 80000
	}
	if r.Kind == "directory" {
		return 50000 - len(r.Identity)
	}
	return 0
}
func compatibleBundle(b bundle.Manifest, m legacyhost.InstallationManifest) bool {
	format, schema, metadata := false, false, false
	for _, v := range b.FormatVersions {
		format = format || v == m.FormatVersion
	}
	for _, v := range b.SchemaVersions {
		schema = schema || v == m.SchemaVersion
	}
	for _, v := range b.HostfsMetadataVersions {
		metadata = metadata || v == bundle.HostfsMetadataVersion
	}
	return format && schema && metadata
}
