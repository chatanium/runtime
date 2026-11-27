//go:build linux

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"sort"
)

type terminalAdmissionKey struct{}
type terminalAdmission struct {
	approval   PurgeApproval
	guard      *host.ManagementGuard
	capability host.TerminalCapability
	ready      bool
}

func preparePurgeAdmission(ctx context.Context, store *host.Store) error {
	admission, ok := ctx.Value(terminalAdmissionKey{}).(*terminalAdmission)
	if !ok || admission == nil || admission.guard == nil || admission.guard.Mode() != host.ManagementExclusive {
		return errors.New("purge requires its continuous exclusive management admission")
	}
	m, e := store.Installation(ctx)
	if e != nil {
		return e
	}
	if m.ActiveRevision != admission.approval.ExpectedActiveRevision {
		return errors.New("purge revision changed before destructive admission")
	}
	records, e := purgeRecords(ctx, store, admission.approval.Scope)
	if e != nil {
		return e
	}
	if e = validateExactPurgeClosure(records, m, admission.approval.Scope); e != nil {
		return e
	}
	if e = preflightTerminalControl(ctx, store, m, admission.approval, records); e != nil {
		return e
	}
	if e = preflightPurgeEvidence(ctx, store, m, admission.approval, records); e != nil {
		return e
	}
	backingSelected := false
	for _, object := range admission.approval.Scope {
		backingSelected = backingSelected || object.Kind == "backing" && object.Identity == m.Paths.BackingFile
	}
	mountedStorage, e := purgeMountedStorage(records, m, backingSelected)
	if e != nil {
		return e
	}
	for _, object := range admission.approval.Scope {
		found := false
		for _, record := range records {
			if record.Kind != object.Kind || record.Identity != object.Identity {
				continue
			}
			digest, err := ObjectObservationDigest(record.Observed)
			if err != nil {
				return err
			}
			if digest != object.ObservationDigest {
				continue
			}
			if e = authorizePurgeRecord(ctx, store, record, object); e != nil {
				return e
			}
			if !insideStorage(record, m) && !(record.Kind == "directory" && record.Identity == m.Paths.StorageRoot && mountedStorage) {
				if e = matchPurgeRecord(ctx, store, record); e != nil {
					return e
				}
			}
			found = true
			break
		}
		if !found {
			return errors.New("purge approval contains an object without exact observed ownership")
		}
	}
	capability, e := terminalCapabilityPreflight(ctx, admission.guard, store, admission.approval)
	if e != nil {
		return e
	}
	admission.capability, admission.ready = capability, true
	return nil
}

// Receipt-first dispatch never opens SQLite when a named terminal authority exists.
func terminalApprovedPlan(ctx context.Context, guard *host.ManagementGuard, id RuntimeInstallationID) (PurgeApproval, bool, error) {
	var plan PurgeApproval
	c, e := terminalNativeFromGuard(guard, id)
	if e != nil {
		return plan, false, e
	}
	defer c.Close()
	if original, found, err := c.approvedPlan(ctx); found || err != nil {
		return original, found, err
	}
	control, e := controlPath(id)
	if e != nil {
		return plan, false, e
	}
	store, e := host.OpenTerminalPurgeMetadata(ctx, control, string(id), guard)
	if errors.Is(e, sql.ErrNoRows) {
		return plan, false, nil
	}
	if e != nil {
		return plan, false, e
	}
	defer store.Close()
	fence, e := store.TerminalPurgeFence(ctx)
	if errors.Is(e, sql.ErrNoRows) {
		return terminalProbeApprovedPlan(ctx, store, id)
	}
	if e != nil {
		return plan, true, e
	}
	if e = gvxcontract.DecodeStrict(fence.ApprovedPlan, terminalReceiptMax, 32, &plan); e != nil {
		return plan, true, e
	}
	digest, e := PurgePlanDigest(plan)
	if e != nil || digest != plan.PlanDigest || plan.InstallationID != id || plan.PlanID != fence.TransactionID || plan.PlanDigest != fence.ApprovalDigest {
		return plan, true, errors.New("terminal source approval provenance differs")
	}
	return plan, true, nil
}

func (c *terminalNativeContext) verifySource(ctx context.Context, receipt terminalReceipt) error {
	if e := c.validateReceipt(receipt); e != nil {
		return e
	}
	if e := terminalCheckAbsence(receipt); e != nil {
		return e
	}
	actual, e := terminalObserve(receipt.Source.Database.Path)
	if e != nil {
		return e
	}
	if !actual.Absent {
		if c.guard == nil {
			return errors.New("coexisting terminal SQLite requires canonical host authority")
		}
		return host.VerifyTerminalPurgeSource(ctx, c.guard, receipt.Authority)
	}
	// Once SQLite is absent, only the immutable receipt may advance. A surviving
	// witness must still be exactly the source-frozen inode/content, never repaired.
	witness, e := terminalObserve(receipt.Source.Witness.Path)
	if e != nil {
		return e
	}
	if !witness.Absent {
		return terminalMatch(receipt.Source.Witness)
	}
	return nil
}

func (c *terminalNativeContext) validateAuthority(receipt terminalReceipt) error {
	authority := receipt.Authority
	if e := validateTerminalPlacementAt(receipt.Approval, c.rootPath, c.receiptPath); e != nil {
		return e
	}
	if authority.Version != 1 || authority.InstallationID != string(receipt.InstallationID) || authority.Incarnation != receipt.Incarnation || authority.TransactionID != receipt.TransactionID || authority.ApprovalDigest != receipt.Approval.PlanDigest || authority.ReceiptPath != c.receiptPath || len(authority.Remaining) != len(receipt.Targets) || len(authority.AbsenceGuards) != len(receipt.Guards) {
		return errors.New("terminal native seal differs from receipt authority")
	}
	var approval PurgeApproval
	if e := gvxcontract.DecodeStrict(authority.ApprovedPlan, terminalReceiptMax, 32, &approval); e != nil {
		return e
	}
	digest, e := PurgePlanDigest(approval)
	if e != nil || digest != receipt.Approval.PlanDigest {
		return errors.New("terminal typed seal approval differs")
	}
	if receipt.Source.Control != terminalNativeIdentity(authority.SourceControl) || receipt.Source.Database != terminalNativeIdentity(authority.SourceDatabase) || receipt.Source.Witness != terminalNativeIdentity(authority.FrozenManifest) {
		return errors.New("terminal source native identities differ")
	}
	control := c.controlPath
	if receipt.Source.Control.Path != control || receipt.Source.Database.Path != filepath.Join(control, "supervisor.sqlite") || receipt.Source.Witness.Path != filepath.Join(control, "installation.json") {
		return errors.New("terminal source identities are not the fixed installation control files")
	}
	allowed := map[string]bool{}
	for _, name := range terminalControlNames {
		allowed[filepath.Join(control, name)] = true
	}
	selectedDirectories := map[string]bool{}
	for _, object := range receipt.Approval.Scope {
		if object.Kind == "directory" {
			selectedDirectories[object.Identity] = true
		}
	}
	if !selectedDirectories[control] {
		return errors.New("terminal approval does not select its control directory")
	}
	for index, target := range receipt.Targets {
		if target.Native != terminalNativeIdentity(authority.Remaining[index].Native) {
			return errors.New("terminal target differs from source-bound native seal")
		}
		if !allowed[target.Native.Path] && !(selectedDirectories[target.Native.Path] && (target.Native.Path == control || isAncestor(target.Native.Path, control))) {
			return errors.New("terminal target is outside the finite approved control closure")
		}
	}
	for index, guard := range receipt.Guards {
		source := authority.AbsenceGuards[index]
		if guard.Kind != source.Kind || guard.Path != source.Path || guard.Name != source.Name || guard.UID != source.UID || guard.GID != source.GID || guard.GroupOnly != source.GroupOnly {
			return errors.New("terminal absence guard differs from frozen source")
		}
		if guard.Kind == "account" {
			if e := validateTerminalAccountGuard(guard); e != nil {
				return e
			}
		} else if guard.Kind != "path" || guard.GroupOnly || !filepath.IsAbs(guard.Path) || filepath.Clean(guard.Path) != guard.Path || guard.Path == "/" || guard.Path == c.rootPath {
			return errors.New("terminal path guard is invalid")
		}
	}
	return nil
}

var terminalControlNames = [...]string{"runtime.sock", "management.sock", "installation.json.next", "supervisor.sqlite-wal", "supervisor.sqlite-shm", "supervisor.sqlite", "installation.json", "installation.lock"}

func terminalCaptureTargets(m host.InstallationManifest, ancestors []host.ProvisionRecord) ([]host.TerminalObject, error) {
	paths := make([]string, 0, len(terminalControlNames)+len(ancestors)+1)
	for _, name := range terminalControlNames {
		paths = append(paths, filepath.Join(m.Paths.Control, name))
	}
	paths = append(paths, m.Paths.Control)
	sort.Slice(ancestors, func(i, j int) bool { return len(ancestors[i].Identity) > len(ancestors[j].Identity) })
	for _, ancestor := range ancestors {
		paths = append(paths, ancestor.Identity)
	}
	targets := make([]host.TerminalObject, 0, len(paths))
	allowed := map[string]bool{}
	for _, path := range paths {
		allowed[path] = true
	}
	for _, path := range paths {
		native, e := terminalObserve(path)
		if e != nil {
			return nil, e
		}
		if !native.Absent {
			base := filepath.Base(path)
			socket := filepath.Dir(path) == m.Paths.Control && (base == "runtime.sock" || base == "management.sock")
			directory := path == m.Paths.Control || isAncestor(path, m.Paths.Control)
			if native.UID != 0 {
				return nil, errors.New("terminal control object is not root-owned")
			}
			if socket {
				mode, gid := uint32(0600), uint32(0)
				if base == "runtime.sock" {
					mode, gid = 0660, m.Identities.App.GID
				}
				if native.Kind != "socket" || native.Mode != mode || native.GID != gid || native.Links != 1 {
					return nil, errors.New("terminal socket differs from its fixed ownership policy")
				}
			} else if directory {
				if native.Kind != "directory" || native.Mode&0022 != 0 {
					return nil, errors.New("terminal ancestor is not a protected directory")
				}
			} else if native.Kind != "file" || native.GID != 0 || native.Mode != 0600 || native.Links != 1 {
				return nil, errors.New("terminal metadata is not a private root single-link regular file")
			}
			if native.Kind == "directory" {
				entries, e := os.ReadDir(path)
				if e != nil {
					return nil, e
				}
				for _, entry := range entries {
					if !allowed[filepath.Join(path, entry.Name())] {
						return nil, errors.New("terminal closure contains an unapproved child")
					}
				}
			}
		}
		targets = append(targets, host.TerminalObject{Name: filepath.Base(path), Native: host.TerminalNativeIdentity(native)})
	}
	return targets, nil
}

func terminalCaptureGuards(ctx context.Context, store *host.Store, m host.InstallationManifest, approval PurgeApproval, extras []host.ProvisionRecord, targets []host.TerminalObject) ([]host.TerminalGuard, error) {
	remaining := map[string]bool{}
	for _, target := range targets {
		remaining[target.Native.Path] = true
	}
	records := append([]host.ProvisionRecord(nil), extras...)
	for _, object := range approval.Scope {
		history, e := store.ObjectProvisions(ctx, object.Kind, object.Identity)
		if e != nil {
			return nil, e
		}
		found := false
		for _, record := range history {
			if !record.ProductCreated || record.ExistedBefore || record.State != "OBSERVED" {
				continue
			}
			digest, e := ObjectObservationDigest(record.Observed)
			if e != nil {
				return nil, e
			}
			if digest == object.ObservationDigest {
				records = append(records, record)
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("terminal source lost approved historical ownership")
		}
	}
	guards := []host.TerminalGuard{}
	seen := map[string]bool{}
	for _, record := range records {
		if insideStorage(record, m) {
			continue
		}
		path, e := purgeRecordPath(record)
		if e != nil {
			return nil, e
		}
		if remaining[path] {
			continue
		}
		var guard host.TerminalGuard
		if record.Kind == "account" {
			var properties host.ProvisionProperties
			if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &properties); e != nil {
				return nil, e
			}
			guard = host.TerminalGuard{Kind: "account", RecordID: record.ID, Name: properties.Name, UID: properties.UID, GID: properties.GID, GroupOnly: properties.Source == "group"}
			if e = validateTerminalAccountGuard(terminalAbsenceGuard{Kind: guard.Kind, Name: guard.Name, UID: guard.UID, GID: guard.GID, GroupOnly: guard.GroupOnly}); e != nil {
				return nil, e
			}
		} else {
			if path == "" {
				continue
			}
			guard = host.TerminalGuard{Kind: "path", RecordID: record.ID, Path: path}
			if record.Kind == "backing" {
				guard.UUID = m.Backing.XFSUUID
			}
		}
		key := guard.Kind + ":" + guard.Path + ":" + guard.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		if e = completedObjectAbsent(record); e != nil {
			return nil, e
		}
		guards = append(guards, guard)
	}
	sort.Slice(guards, func(i, j int) bool {
		a, b := guards[i], guards[j]
		return a.Kind+":"+a.Path+":"+a.Name < b.Kind+":"+b.Path+":"+b.Name
	})
	return guards, nil
}

func (c *terminalNativeContext) receiptFromFence(fence host.TerminalFence, approval PurgeApproval) (terminalReceipt, error) {
	receipt := terminalReceipt{Version: terminalReceiptVersion, InstallationID: approval.InstallationID, Incarnation: fence.Incarnation, TransactionID: fence.TransactionID, Approval: approval, Revision: 2}
	receipt.Source = terminalSource{Control: terminalNativeIdentity(fence.SourceControl), Database: terminalNativeIdentity(fence.SourceDatabase), Witness: terminalNativeIdentity(fence.FrozenManifest)}
	receipt.Authority = host.TerminalPurgeSeal{Version: 1, InstallationID: string(approval.InstallationID), Incarnation: fence.Incarnation, TransactionID: fence.TransactionID, ApprovalDigest: approval.PlanDigest, ApprovedPlan: fence.ApprovedPlan, ReceiptPath: c.receiptPath, SourceControl: fence.SourceControl, SourceDatabase: fence.SourceDatabase, FrozenManifest: fence.FrozenManifest, Remaining: fence.Remaining, AbsenceGuards: fence.AbsenceGuards}
	for _, target := range fence.Remaining {
		receipt.Targets = append(receipt.Targets, terminalTarget{Native: terminalNativeIdentity(target.Native)})
	}
	for _, guard := range fence.AbsenceGuards {
		receipt.Guards = append(receipt.Guards, terminalAbsenceGuard{Kind: guard.Kind, Path: guard.Path, Name: guard.Name, UID: guard.UID, GID: guard.GID, GroupOnly: guard.GroupOnly})
	}
	var e error
	receipt.SealDigest, e = terminalImmutableDigest(receipt)
	return receipt, e
}

func terminalPublishFenced(ctx context.Context, guard *host.ManagementGuard, store *host.Store, fence host.TerminalFence, approval PurgeApproval) (terminalReceipt, error) {
	c, e := terminalNativeFromGuard(guard, approval.InstallationID)
	if e != nil {
		return terminalReceipt{}, e
	}
	defer c.Close()
	receipt, e := c.receiptFromFence(fence, approval)
	if e != nil {
		return receipt, e
	}
	var attempt uint64
	old, e := store.TerminalPurgePublication(ctx)
	if e == nil {
		var previous terminalReceipt
		if e = gvxcontract.DecodeStrict(old.Payload, terminalReceiptMax, 32, &previous); e != nil {
			return receipt, e
		}
		if e = c.validateReceipt(previous); e != nil {
			return receipt, e
		}
		if previous.SealDigest != receipt.SealDigest || previous.Revision != 2 {
			return receipt, errors.New("terminal publication replay changed immutable authority")
		}
		attempt = old.Attempt
	} else if !errors.Is(e, sql.ErrNoRows) {
		return receipt, e
	}
	root := c.root
	if e = terminalRejectStaging(root, approval.InstallationID); e != nil {
		return receipt, e
	}
	file, native, e := terminalAnonymous(root)
	if e != nil {
		return receipt, e
	}
	defer file.Close()
	native.Path = c.receiptPath
	receipt.Publication = native
	if e = c.validateReceipt(receipt); e != nil {
		return receipt, e
	}
	raw, e := json.Marshal(receipt)
	if e != nil {
		return receipt, e
	}
	if e = terminalWriteAnonymous(file, raw); e != nil {
		return receipt, e
	}
	if _, e = store.BindTerminalPurgePublication(ctx, guard, receipt.Authority, file, raw, attempt); e != nil {
		return receipt, e
	}
	if e = terminalLink(root, file, filepath.Base(native.Path)); e != nil {
		return receipt, e
	}
	if e = root.Sync(); e != nil {
		return receipt, e
	}
	published, _, e := c.read(filepath.Base(native.Path))
	if e != nil {
		return receipt, e
	}
	if !terminalPublicationMatches(published.Publication, native) || published.SealDigest != receipt.SealDigest {
		return receipt, errors.New("terminal publication did not expose the exact source-bound complete inode")
	}
	return published, host.VerifyTerminalPurgeSource(ctx, guard, published.Authority)
}

func (c *terminalNativeContext) finish(ctx context.Context, receipt terminalReceipt) (RemovalResult, error) {
	result := RemovalResult{InstallationID: receipt.InstallationID}
	if e := c.verifySource(ctx, receipt); e != nil {
		return result, e
	}
	root := c.root
	receipt, e := c.settleStage(receipt)
	if e != nil {
		return result, e
	}
	receipt, e = c.resumeFiles(ctx, receipt)
	if e != nil {
		return result, e
	}
	if e = terminalMatch(receipt.Publication); e != nil {
		return result, e
	}
	if e = unix.Unlinkat(int(root.Fd()), filepath.Base(c.receiptPath), 0); e != nil {
		return result, e
	}
	if e = root.Sync(); e != nil {
		return result, e
	}
	for _, target := range receipt.Targets {
		result.Removed = append(result.Removed, ObjectResult{Kind: target.Native.Kind, Identity: target.Native.Path, State: "removed"})
	}
	result.Preserved = append(result.Preserved, ObjectResult{Kind: "shared-management-anchor", Identity: filepath.Join(c.rootPath, ".management.lock"), State: "preserved"}, ObjectResult{Kind: "directory", Identity: c.rootPath, State: "preserved"})
	return result, nil
}

func terminalResumeSource(ctx context.Context, guard *host.ManagementGuard, id RuntimeInstallationID, approval PurgeApproval) (RemovalResult, bool, error) {
	result := RemovalResult{InstallationID: id}
	c, e := terminalNativeFromGuard(guard, id)
	if e != nil {
		return result, false, e
	}
	defer c.Close()
	if completed, found, err := c.resumeSource(ctx, approval); found || err != nil {
		return completed, found, err
	}
	control, e := controlPath(id)
	if e != nil {
		return result, false, e
	}
	store, e := host.OpenTerminalPurgeSource(ctx, control, string(id), guard)
	if errors.Is(e, sql.ErrNoRows) {
		return result, false, nil
	}
	if e != nil {
		return result, false, e
	}
	defer store.Close()
	fence, e := store.TerminalPurgeFence(ctx)
	if errors.Is(e, sql.ErrNoRows) {
		return result, false, nil
	}
	if e != nil {
		return result, true, e
	}
	if fence.ApprovalDigest != approval.PlanDigest || fence.TransactionID != approval.PlanID {
		return result, true, errors.New("fenced source requires the exact original purge approval")
	}
	lease, e := store.AcquireLease(ctx)
	if e != nil {
		return result, true, e
	}
	defer lease.Close()
	if !fence.Frozen {
		capability, err := terminalCapabilityPreflight(ctx, guard, store, approval)
		if err != nil {
			return result, true, err
		}
		// The existing irreversible source fence already contains cleanup proof
		// and every target. This branch only finishes its recorded publication;
		// it cannot admit a new fence or rediscover ownership.
		fence, err = store.PrepareTerminalPurge(ctx, guard, capability, fence.ApprovedPlan, fence.TransactionID, host.CleanupEvidence{}, fence.Remaining, fence.AbsenceGuards)
		if err != nil {
			return result, true, err
		}
	}
	receipt, e := terminalPublishFenced(ctx, guard, store, fence, approval)
	if e != nil {
		return result, true, e
	}
	if e = lease.Close(); e != nil {
		return result, true, e
	}
	if e = store.Close(); e != nil {
		return result, true, e
	}
	result, e = c.finish(ctx, receipt)
	return result, true, e
}

func validateTerminalPlacement(approval PurgeApproval) error {
	return validateTerminalPlacementAt(approval, terminalRoot, terminalReceiptPath(approval.InstallationID))
}

func validateTerminalPlacementAt(approval PurgeApproval, rootPath, receiptPath string) error {
	id := approval.InstallationID
	if approval.TerminalReceiptPath != receiptPath || approval.PublicationProbePaths != [2]string{filepath.Join(rootPath, terminalStageName(id, approval.PlanID, 0)), filepath.Join(rootPath, terminalStageName(id, approval.PlanID, 1))} {
		return errors.New("purge terminal authority placement was not explicitly approved")
	}
	if approval.ManagementAnchor.Root.Path != rootPath || approval.ManagementAnchor.Lock.Path != filepath.Join(rootPath, ".management.lock") || approval.ManagementAnchor.Marker != host.ManagementMarker {
		return errors.New("purge shared management infrastructure was not explicitly approved")
	}
	for _, object := range approval.Scope {
		if !filepath.IsAbs(object.Identity) {
			continue
		}
		for _, protected := range []string{rootPath, approval.TerminalReceiptPath, approval.PublicationProbePaths[0], approval.PublicationProbePaths[1], approval.ManagementAnchor.Lock.Path} {
			if object.Identity == protected || isAncestor(object.Identity, protected) {
				return fmt.Errorf("selected purge root overlaps retained terminal authority: %s", object.Identity)
			}
		}
	}
	return nil
}

func verifyApprovedManagementAnchor(ctx context.Context, approved host.ManagementAnchorObservation) error {
	current, e := host.ObserveManagementAnchor(ctx)
	if e != nil {
		return e
	}
	a, b := approved.Root, current.Root
	// Directory link counts reflect other installations, not anchor identity.
	if approved.Marker != current.Marker || approved.Lock != current.Lock || a.Absent || b.Absent || a.Path != b.Path || a.Kind != b.Kind || a.Device != b.Device || a.Inode != b.Inode || a.UID != b.UID || a.GID != b.GID || a.Mode != b.Mode {
		return errors.New("approved shared management anchor native identity changed")
	}
	return nil
}

func validateTerminalAccountGuard(guard terminalAbsenceGuard) error {
	if !validAccountName(guard.Name) || guard.GID == 0 || guard.GroupOnly && guard.UID != 0 || !guard.GroupOnly && guard.UID == 0 {
		return errors.New("terminal account/group guard is not representable by the approved numeric identity")
	}
	return nil
}

func (c *terminalNativeContext) approvedPlan(ctx context.Context) (PurgeApproval, bool, error) {
	receipt, _, e := c.read(filepath.Base(c.receiptPath))
	if os.IsNotExist(e) {
		return PurgeApproval{}, false, nil
	}
	if e != nil {
		return PurgeApproval{}, true, e
	}
	if e = c.verifySource(ctx, receipt); e != nil {
		return PurgeApproval{}, true, e
	}
	return receipt.Approval, true, nil
}

func (c *terminalNativeContext) resumeSource(ctx context.Context, approval PurgeApproval) (RemovalResult, bool, error) {
	result := RemovalResult{InstallationID: c.installationID}
	receipt, _, e := c.read(filepath.Base(c.receiptPath))
	if os.IsNotExist(e) {
		return result, false, nil
	}
	if e != nil {
		return result, true, e
	}
	if receipt.Approval.PlanDigest != approval.PlanDigest {
		return result, true, errors.New("terminal retry requires the original full approved purge plan")
	}
	result, e = c.finish(ctx, receipt)
	return result, true, e
}

func terminalFinish(ctx context.Context, guard *host.ManagementGuard, receipt terminalReceipt) (RemovalResult, error) {
	c, e := terminalNativeFromGuard(guard, receipt.InstallationID)
	if e != nil {
		return RemovalResult{InstallationID: receipt.InstallationID}, e
	}
	defer c.Close()
	return c.finish(ctx, receipt)
}
