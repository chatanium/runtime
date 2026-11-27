//go:build linux

package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"slices"
	"strings"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/gvxstage"
	"github.com/thirdscam/chatanium/internal/provision"
	"golang.org/x/sys/unix"
)

func preparationProgram(purpose string) string {
	switch purpose {
	case gvxstage.PreparationPurpose:
		return "preparer"
	case gvxstage.LoadPurpose:
		return "rungv"
	}
	return ""
}

func preparationUnitName(name string) bool {
	return strings.HasPrefix(name, "chatanium-image-preparer-") || strings.HasPrefix(name, "chatanium-image-rungv-")
}

func preparationAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}

func validatePreparationRoot(root NativeRootIdentity) error {
	if root.RootID == "" || len(root.RootID) > 4096 || !preparationAbsolute(root.HostPath) || root.Dev == 0 || root.Ino == 0 || root.Mode&^uint32(07777) != 0 {
		return invalid("incomplete preparation native storage identity")
	}
	return nil
}

func validatePreparationLayout(launch PreparationWriterLaunch) error {
	view := launch.Layout
	if view.Version != gvxcontract.PreparationWriterDomainVersion || view.JobID != launch.JobID || view.ProvisionID != launch.ProvisionID {
		return invalid("preparation layout version/job differs from launch")
	}
	for _, root := range []PreparationStorageRoot{view.Source, view.Cache, view.Work} {
		if err := validatePreparationRoot(root.Barrier); err != nil {
			return err
		}
		if err := validatePreparationRoot(root.Data); err != nil {
			return err
		}
		if root.Barrier.Dev != root.Data.Dev || root.Data.Project == 0 || root.Barrier.UID != 0 || root.Barrier.GID != 0 || root.Barrier.Mode != 0700 {
			return invalid("preparation layout lacks private native birth barrier/project")
		}
		if root.ReadOnly {
			if root.Data.UID != 0 || root.Data.Mode&0222 != 0 || root.Data.Mode&0500 != 0500 {
				return invalid("preparation readonly source is not root sealed")
			}
		} else if root.Data.UID != launch.PreparerUID || root.Data.GID != launch.PreparerGID || root.Data.Mode != 0700 {
			return invalid("preparation mutable data differs from dedicated identity")
		}
	}
	root := filepath.Dir(filepath.Dir(view.Cache.Barrier.HostPath))
	sourceJob := filepath.Base(view.Source.Data.HostPath)
	if !safeID(sourceJob) || view.Source.Barrier.HostPath != filepath.Join(root, "images") || view.Source.Data.HostPath != filepath.Join(root, "images", sourceJob) ||
		view.Cache.Barrier.HostPath != filepath.Join(root, "prepared", launch.JobID) || view.Cache.Data.HostPath != filepath.Join(view.Cache.Barrier.HostPath, "generation") ||
		view.Work.Barrier.HostPath != filepath.Join(root, "preparation") || view.Work.Data.HostPath != filepath.Join(root, "preparation", launch.JobID) ||
		view.Cache.ReadOnly || view.Work.ReadOnly || view.Cache.Barrier.Project != view.Cache.Data.Project ||
		view.Source.Data.Dev != view.Cache.Data.Dev || view.Work.Data.Dev != view.Cache.Data.Dev {
		return invalid("preparation layout changed fixed inner paths or project domain")
	}
	if launch.Purpose == gvxstage.LoadPurpose && !view.Source.ReadOnly {
		return invalid("loader requires readonly original source")
	}
	return nil
}

func validatePreparationLaunch(launch PreparationWriterLaunch) error {
	return validatePreparationLaunchFilter(launch, gvxcontract.PreparationWriterFilterVersion)
}

func validatePreparationLaunchFilter(launch PreparationWriterLaunch, filterVersion uint32) error {
	if launch.FilterVersion != filterVersion && !(filterVersion == 1 && launch.FilterVersion == 0) {
		return invalid("preparation launch lacks exact supported filter intent")
	}
	program := preparationProgram(launch.Purpose)
	if launch.Version != gvxcontract.PreparationWriterDomainVersion || launch.ProtocolVersion != gvxcontract.PreparationWriterProtocolVersion ||
		!safeID(launch.InstallationID) || !safeID(launch.JobID) || !safeID(launch.ProvisionID) || !safeID(launch.Generation) || launch.BootID == "" ||
		program == "" || launch.UnitName != "chatanium-image-"+program+"-"+launch.Generation+".service" || launch.PreparerUID == 0 || launch.PreparerGID == 0 {
		return invalid("invalid current preparation launch binding")
	}
	for _, digest := range []string{launch.BundleDigest, launch.StageDigest, launch.TargetDigest, launch.ArgumentDigest, launch.DeclarationDigest} {
		if !provision.ValidDigest(digest) {
			return invalid("preparation launch lacks exact artifact/declaration digest")
		}
	}
	for _, path := range []string{launch.StagePath, launch.TargetPath} {
		if !preparationAbsolute(path) || !strings.HasPrefix(path, "/chatanium/base/") {
			return invalid("preparation executable is outside the fixed verified base")
		}
	}
	if launch.StagePath == launch.TargetPath {
		return invalid("preparation stage cannot replace the original target")
	}
	return validatePreparationLayout(launch)
}

func validatePreparationTasks(snapshot PreparationTaskSnapshot, launch PreparationWriterLaunch) error {
	if snapshot.ThreadCount == 0 || !provision.ValidDigest(snapshot.SnapshotDigest) || !snapshot.NoNewPrivileges || snapshot.SupplementaryGID != launch.PreparerGID ||
		snapshot.Capabilities != [5]uint64{} || snapshot.SeccompMode != 0 && snapshot.SeccompMode != 2 || snapshot.SeccompMode == 0 && snapshot.SeccompFilters != 0 || snapshot.SeccompMode == 2 && snapshot.SeccompFilters == 0 {
		return invalid("preparation tasks lack exact zero-authority native snapshot")
	}
	for index := range snapshot.UIDs {
		if snapshot.UIDs[index] != launch.PreparerUID || snapshot.GIDs[index] != launch.PreparerGID {
			return invalid("preparation task credentials differ from launch")
		}
	}
	return nil
}

func validPreparationNamespace(namespace NamespaceIdentity) bool {
	return namespace.Device != 0 && namespace.Inode != 0
}

func validatePreparationWriter(writer PreparationWriterRecord) error {
	return validatePreparationWriterFilter(writer, gvxcontract.PreparationWriterFilterVersion, gvxstage.PreparationFilterDigest())
}

func validatePreparationWriterFilter(writer PreparationWriterRecord, filterVersion uint32, filterDigest string) error {
	if err := validatePreparationLaunchFilter(writer.Launch, filterVersion); err != nil {
		return err
	}
	if writer.StartIntent && writer.StartForbidden {
		return invalid("preparation START conflicts with never-authorized fence")
	}
	if writer.Birth == nil {
		if writer.Evidence != nil || writer.StartIntent || writer.StartForbidden {
			return invalid("preparation authority lacks observed native birth")
		}
		return nil
	}
	birth := writer.Birth
	launch := writer.Launch
	if birth.Version != gvxcontract.PreparationWriterDomainVersion || !validUnit(birth.Unit) || birth.Unit.Name != launch.UnitName || birth.Unit.Generation != launch.Generation || birth.Unit.BootID != launch.BootID ||
		birth.Unit.ExecutableDigest != launch.StageDigest ||
		birth.PeerPID != birth.Unit.MainPID || birth.PeerUID != launch.PreparerUID || birth.PeerGID != launch.PreparerGID || birth.PIDFDDevice == 0 || birth.PIDFDInode == 0 {
		return invalid("preparation birth differs from exact native invocation/artifact/peer")
	}
	if !validPreparationNamespace(birth.UserNamespace) || !validPreparationNamespace(birth.HostUserNamespace) || birth.UserNamespace == birth.HostUserNamespace ||
		birth.ParentUserNamespace != birth.HostUserNamespace || birth.UserNamespaceOwnerUID != 0 || birth.UserNamespaceType != unix.CLONE_NEWUSER || !birth.SetgroupsDenied || !validPreparationNamespace(birth.MountNamespace) {
		return invalid("preparation lacks root-owned direct-child user namespace")
	}
	if birth.UIDMap != [2]PreparationIDMap{{Inside: 0, Outside: 0, Length: 1}, {Inside: launch.PreparerUID, Outside: launch.PreparerUID, Length: 1}} ||
		birth.GIDMap != [2]PreparationIDMap{{Inside: 0, Outside: 0, Length: 1}, {Inside: launch.PreparerGID, Outside: launch.PreparerGID, Length: 1}} {
		return invalid("preparation user namespace mapping differs from exact identities")
	}
	if err := validatePreparationTasks(birth.Tasks, launch); err != nil {
		return err
	}
	if writer.Evidence == nil {
		if writer.StartIntent {
			return invalid("preparation START lacks immutable full evidence")
		}
		return nil
	}
	evidence := writer.Evidence
	if !writer.StartIntent || writer.StartForbidden || evidence.Version != gvxcontract.PreparationWriterDomainVersion || evidence.ProtocolVersion != gvxcontract.PreparationWriterProtocolVersion ||
		evidence.FilterVersion != filterVersion || !provision.ValidDigest(evidence.FilterDigest) || evidence.FilterDigest != filterDigest || evidence.AuditArch != unix.AUDIT_ARCH_X86_64 || evidence.Tasks.SeccompMode != 2 ||
		!evidence.RejectX32 || !evidence.TSYNC || !evidence.FilterReady || birth.Tasks.SeccompFilters == math.MaxUint32 || evidence.Tasks.SeccompFilters != birth.Tasks.SeccompFilters+1 {
		return invalid("preparation START lacks exact acknowledged TSYNC no-export filter")
	}
	return validatePreparationTasks(evidence.Tasks, launch)
}

func validatePreparationWriterProperties(properties ProvisionProperties) error {
	return validatePreparationWriterPropertiesFilter(properties, gvxcontract.PreparationWriterFilterVersion, gvxstage.PreparationFilterDigest())
}

func validatePreparationWriterPropertiesFilter(properties ProvisionProperties, filterVersion uint32, filterDigest string) error {
	if properties.Writer == nil {
		return nil
	}
	if err := validatePreparationWriterFilter(*properties.Writer, filterVersion, filterDigest); err != nil {
		return err
	}
	writer := properties.Writer
	if properties.Name != writer.Launch.UnitName || properties.Unit == nil && (properties.Rejection == "" || writer.Birth != nil) ||
		properties.Unit != nil && (properties.Unit.Name != writer.Launch.UnitName || properties.Unit.Generation != writer.Launch.Generation || properties.Unit.BootID != writer.Launch.BootID) ||
		properties.Limits == nil || properties.Limits.Pids <= 0 {
		return invalid("preparation evidence differs from unit provisioning binding")
	}
	if writer.Birth != nil {
		if *properties.Unit != writer.Birth.Unit || properties.MountNamespace == nil || *properties.MountNamespace != writer.Birth.MountNamespace || properties.MountNamespaceDisposition != NamespacePrivate ||
			int64(writer.Birth.Tasks.ThreadCount) > properties.Limits.Pids {
			return invalid("preparation native birth differs from observed unit/namespace/task budget")
		}
	}
	if writer.Evidence != nil && int64(writer.Evidence.Tasks.ThreadCount) > properties.Limits.Pids {
		return invalid("preparation full snapshot exceeds admitted task limit")
	}
	return nil
}

// Missing fields are an earlier exact prefix, never permission to erase history.
func mergePreparationWriter(old, next *PreparationWriterRecord) (*PreparationWriterRecord, error) {
	if next == nil {
		return old, nil
	}
	if old == nil {
		if err := validatePreparationWriter(*next); err != nil {
			return nil, err
		}
		copy := *next
		return &copy, nil
	}
	if old.Launch != next.Launch {
		return nil, errors.New("preparation launch intent cannot change")
	}
	merged := *old
	if next.Birth != nil {
		if old.Birth != nil && *old.Birth != *next.Birth {
			return nil, errors.New("preparation observed native birth cannot change")
		}
		merged.Birth = next.Birth
	}
	if next.Evidence != nil {
		if old.Evidence != nil && *old.Evidence != *next.Evidence {
			return nil, errors.New("preparation immutable filter evidence cannot change")
		}
		merged.Evidence = next.Evidence
	}
	merged.StartIntent = old.StartIntent || next.StartIntent
	merged.StartForbidden = old.StartForbidden || next.StartForbidden
	if err := validatePreparationWriter(merged); err != nil {
		return nil, err
	}
	return &merged, nil
}

func preparationWriterPrefix(prefix, full *PreparationWriterRecord) bool {
	return prefix != nil && full != nil && prefix.Launch == full.Launch &&
		(prefix.Birth == nil || full.Birth != nil && *prefix.Birth == *full.Birth) &&
		(prefix.Evidence == nil || full.Evidence != nil && *prefix.Evidence == *full.Evidence) &&
		(!prefix.StartIntent || full.StartIntent) && (!prefix.StartForbidden || full.StartForbidden)
}

func readPreparationProvision(ctx context.Context, tx *sql.Tx, id string) (ProvisionRecord, error) {
	var record ProvisionRecord
	var raw []byte
	if err := tx.QueryRowContext(ctx, "SELECT record FROM provisioning_ledger WHERE id=?", id).Scan(&raw); err != nil {
		return record, err
	}
	if err := decodeProvisionRecord(raw, &record); err != nil {
		return record, err
	}
	return record, nil
}

func preparationSpaceRecord(ctx context.Context, tx *sql.Tx, id string) (ProvisionRecord, ImageSpace, error) {
	record, err := readPreparationProvision(ctx, tx, id)
	if err != nil {
		return record, ImageSpace{}, err
	}
	var properties ProvisionProperties
	raw := record.Desired
	if record.State == "OBSERVED" {
		raw = record.Observed.Attributes
	}
	if err = gvxcontract.DecodeStrict(raw, 64<<10, 16, &properties); err != nil {
		return record, ImageSpace{}, err
	}
	if record.Kind != "image" || !record.ProductCreated || record.ExistedBefore || properties.ImageSpace == nil || properties.ImageSpace.ProvisionID != record.ID || record.Identity != "image-space:"+properties.ImageSpace.JobID {
		return record, ImageSpace{}, errors.New("preparation writer lacks original owned space intent")
	}
	return record, *properties.ImageSpace, nil
}

func (s *Store) validatePreparationScope(ctx context.Context, tx *sql.Tx, record ProvisionRecord, properties ProvisionProperties, historical bool) error {
	if properties.Writer == nil {
		return nil
	}
	if record.Kind != "unit" || !preparationUnitName(record.Identity) || !record.ProductCreated || record.ExistedBefore {
		return invalid("writer evidence belongs only to owned fixed preparation units")
	}
	if err := validatePreparationWriterProperties(properties); err != nil {
		return err
	}
	launch := properties.Writer.Launch
	var desired ProvisionProperties
	if err := gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); err != nil {
		return err
	}
	if desired.Name != launch.UnitName || desired.Unit == nil || desired.Unit.Name != launch.UnitName || desired.Unit.Generation != launch.Generation || desired.Unit.BootID != launch.BootID ||
		desired.Limits == nil || properties.Limits == nil || *desired.Limits != *properties.Limits {
		return errors.New("preparation native observation changed original dispatch binding/limits")
	}
	if launch.InstallationID != s.productID {
		return invalid("preparation launch belongs to another installation")
	}
	manifest, err := readManagementManifest(ctx, tx, s.productID)
	if err != nil {
		return err
	}
	if launch.PreparerUID != manifest.Identities.Preparer.UID || launch.PreparerGID != manifest.Identities.Preparer.GID ||
		launch.Layout.Cache.Barrier.HostPath != filepath.Join(manifest.Paths.StorageRoot, "prepared", launch.JobID) {
		return errors.New("preparation launch changed installed identity/bundle/storage authority")
	}
	_, space, err := preparationSpaceRecord(ctx, tx, launch.ProvisionID)
	if err != nil {
		return err
	}
	view := launch.Layout
	if space.JobID != launch.JobID || space.Source != view.Source.Data.HostPath || space.Cache != view.Cache.Barrier.HostPath || space.Work != view.Work.Data.HostPath ||
		space.SourceProject != view.Source.Data.Project || space.CacheProject != view.Cache.Data.Project || space.WorkProject != view.Work.Data.Project || space.ReusedSource && !view.Source.ReadOnly {
		return errors.New("preparation layout differs from exact journaled space/projects")
	}
	if !historical {
		if err := validatePreparationLaunchBundleTx(ctx, tx, s.productID, launch, space); err != nil {
			return err
		}
	}
	if record.ID == "systemd-"+launch.Generation {
		if desired.Writer == nil || desired.Writer.Launch != launch || desired.Writer.Birth != nil || desired.Writer.Evidence != nil || desired.Writer.StartIntent || desired.Writer.StartForbidden ||
			properties.Source != preparationProgram(launch.Purpose) || desired.Source != properties.Source {
			return invalid("internal preparation unit lacks exact original pre-dispatch launch intent")
		}
		return nil
	}
	if properties.Source != launch.JobID || desired.Source != launch.JobID {
		return invalid("outer preparation evidence belongs to a different original job")
	}
	internal, err := readPreparationProvision(ctx, tx, "systemd-"+launch.Generation)
	if err != nil {
		return err
	}
	if internal.Kind != "unit" || internal.Identity != record.Identity || internal.State != "OBSERVED" {
		return errors.New("outer writer evidence lacks observed original internal unit")
	}
	var captured ProvisionProperties
	if err = gvxcontract.DecodeStrict(internal.Observed.Attributes, 64<<10, 16, &captured); err != nil {
		return err
	}
	if !preparationWriterPrefix(properties.Writer, captured.Writer) || captured.Unit == nil || properties.Unit == nil || *captured.Unit != *properties.Unit {
		return errors.New("outer writer evidence was not copied from the exact original internal unit")
	}
	return nil
}

func (s *Store) mergePreparationObservation(ctx context.Context, tx *sql.Tx, record ProvisionRecord, desired, old ProvisionProperties, next *ProvisionProperties) error {
	writer, err := mergePreparationWriter(desired.Writer, old.Writer)
	if err != nil {
		return err
	}
	writer, err = mergePreparationWriter(writer, next.Writer)
	if err != nil {
		return err
	}
	if writer == nil {
		return nil
	}
	newAdmission := record.ID == "systemd-"+writer.Launch.Generation &&
		(writer.Birth != nil && (old.Writer == nil || old.Writer.Birth == nil) || writer.Evidence != nil && (old.Writer == nil || old.Writer.Evidence == nil))
	if record.ID == "systemd-"+writer.Launch.Generation {
		if writer.StartForbidden && (old.Writer == nil || !old.Writer.StartForbidden) {
			return errors.New("use atomic exact-birth ForbidPreparationWriterStart before no-START cleanup")
		}
		if writer.Evidence != nil && (old.Writer == nil || old.Writer.Evidence == nil) && (record.State != "OBSERVED" || old.Writer == nil || old.Writer.Birth == nil) {
			return errors.New("preparation full evidence requires durably recorded birth before ARM")
		}
	}
	next.Writer = writer
	// Eager native terminal observation and gate evidence advance independently.
	// Preserve a more complete native prefix when the other writer was stale.
	if next.Unit == nil && next.Rejection == "" {
		next.Unit = old.Unit
	}
	if next.Exit == nil {
		next.Exit = old.Exit
	}
	if next.JobPath == "" {
		next.JobPath = old.JobPath
	}
	if len(next.TransportPipes) == 0 {
		next.TransportPipes = old.TransportPipes
	}
	if next.MountNamespace == nil {
		next.MountNamespace = old.MountNamespace
		next.MountNamespaceDisposition = old.MountNamespaceDisposition
	}
	if next.Absence == nil && old.Absence != nil {
		next.Absence = old.Absence
		next.CgroupEmpty = old.CgroupEmpty
	}
	return s.validatePreparationScope(ctx, tx, record, *next, !newAdmission)
}

// PreparationWriter is a typed historical lookup, not permission to execute.
func (s *Store) PreparationWriter(ctx context.Context, ledgerID string) (PreparationWriterRecord, error) {
	record, err := s.Provision(ctx, ledgerID)
	if err != nil {
		return PreparationWriterRecord{}, err
	}
	var desired, observed ProvisionProperties
	if err = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); err != nil {
		return PreparationWriterRecord{}, err
	}
	if record.State == "OBSERVED" {
		if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &observed); err != nil {
			return PreparationWriterRecord{}, err
		}
	}
	if observed.Writer != nil && (observed.Writer.Launch.FilterVersion != gvxcontract.PreparationWriterFilterVersion ||
		observed.Writer.Evidence != nil && observed.Writer.Evidence.FilterVersion != gvxcontract.PreparationWriterFilterVersion) {
		return PreparationWriterRecord{}, errors.New("unsupported historical preparation is not current writer-domain authority")
	}
	writer, err := mergePreparationWriter(desired.Writer, observed.Writer)
	if err != nil {
		return PreparationWriterRecord{}, err
	}
	if writer == nil {
		return PreparationWriterRecord{}, sql.ErrNoRows
	}
	if record.Kind != "unit" || !preparationUnitName(record.Identity) {
		return PreparationWriterRecord{}, invalid("writer history belongs to a different object kind")
	}
	if record.ID == "systemd-"+writer.Launch.Generation && desired.Writer == nil {
		return PreparationWriterRecord{}, errors.New("writer evidence lacks original pre-dispatch launch intent")
	}
	return *writer, validatePreparationWriter(*writer)
}

// ForbidPreparationWriterStart causally fences a born current-protocol stage.
// It grants no absence, mount, data reclamation or legacy cleanup authority.
func (s *Store) ForbidPreparationWriterStart(ctx context.Context, ledgerID string, birth PreparationWriterBirth) error {
	return s.changeProvision(ctx, ledgerID, func(tx *sql.Tx, record *ProvisionRecord) error {
		if record.CleanupState == "COMPLETE" || record.State != "OBSERVED" {
			return errors.New("never-authorized fence requires current observed incomplete history")
		}
		var desired, observed ProvisionProperties
		if err := gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); err != nil {
			return err
		}
		if err := gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &observed); err != nil {
			return err
		}
		if desired.Writer == nil || observed.Writer == nil || ledgerID != "systemd-"+observed.Writer.Launch.Generation || observed.Writer.Birth == nil || *observed.Writer.Birth != birth || observed.Writer.StartIntent || observed.Writer.Evidence != nil {
			return errors.New("never-authorized fence lacks exact current protocol birth or START already authorized")
		}
		if err := s.validatePreparationScope(ctx, tx, *record, observed, true); err != nil {
			return err
		}
		writer := *observed.Writer
		writer.StartForbidden = true
		if err := validatePreparationWriter(writer); err != nil {
			return err
		}
		observed.Writer = &writer
		raw, err := jsonPreparationProperties(observed)
		if err != nil {
			return err
		}
		record.Observed.Attributes = raw
		return nil
	})
}

func jsonPreparationProperties(properties ProvisionProperties) ([]byte, error) {
	raw, err := json.Marshal(properties)
	if err != nil {
		return nil, err
	}
	if len(raw) > 64<<10 {
		return nil, invalid("preparation observation exceeds provision JSON bound")
	}
	return raw, nil
}

func validatePreparationSettlement(properties ProvisionProperties) error {
	if err := validatePreparationWriterProperties(properties); err != nil {
		return err
	}
	return validateStoredPreparationSettlement(properties)
}

func validateStoredPreparationSettlement(properties ProvisionProperties) error {
	if properties.Writer == nil || properties.Writer.Birth == nil || properties.Absence == nil || properties.Unit == nil || !properties.CgroupEmpty || len(properties.TransportPipes) == 0 || properties.Absence.QuotaReclaimed {
		return errors.New("preparation writer lacks actual scoped native settlement")
	}
	// Admission validated the then-current boot at persistence time. Historical
	// immutable closure remains valid after reboot and passive reads do no probes.
	absence := properties.Absence
	if absence.BootID == "" || len(absence.Units) != 1 || absence.Units[0] != *properties.Unit || !absence.JobsAbsent || !absence.ProcessesAbsent || !absence.TransportsClosed || !absence.MountsAbsent || !absence.OpenReferencesAbsent {
		return errors.New("stored preparation native settlement is incomplete")
	}
	var details UnitAbsenceDetails
	if err := gvxcontract.DecodeStrict(properties.Absence.Details, 64<<10, 8, &details); err != nil {
		return err
	}
	if !details.UnitAbsent || !details.CgroupEmpty || !slices.Equal(details.TransportPipes, properties.TransportPipes) {
		return errors.New("stored preparation unit/transport settlement changed")
	}
	if !details.WriterUserNamespaceAbsent || details.WriterUserNamespace == nil || *details.WriterUserNamespace != properties.Writer.Birth.UserNamespace {
		return errors.New("preparation writer namespace lacks exact native task and FD-reference closure")
	}
	return nil
}

func (s *Store) validatePreparationCompletion(ctx context.Context, tx *sql.Tx, record ProvisionRecord, e CleanupEvidence) error {
	if record.Kind != "unit" || !preparationUnitName(record.Identity) || record.CleanupState == "COMPLETE" {
		return nil
	}
	var desired, observed ProvisionProperties
	if err := gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); err != nil {
		return err
	}
	if record.State == "OBSERVED" {
		if err := gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &observed); err != nil {
			return err
		}
	}
	// Existing causal never-dispatched/rejected cleanup remains separate.
	if record.State == "INTENT" || observed.Rejection != "" {
		if desired.Writer != nil && (desired.Writer.Birth != nil || desired.Writer.Evidence != nil || desired.Writer.StartIntent || desired.Writer.StartForbidden) {
			return invalid("dispatch intent contains fabricated native authority")
		}
		if observed.Writer != nil && observed.Writer.Birth != nil {
			return errors.New("born preparation stage cannot become a dispatch rejection")
		}
		return nil
	}
	if observed.Writer == nil {
		return errors.New("observed legacy preparation lacks writer-domain completion proof")
	}
	if err := s.validatePreparationScope(ctx, tx, record, observed, true); err != nil {
		return err
	}
	if !observed.Writer.StartIntent && !observed.Writer.StartForbidden {
		return errors.New("born preparation cleanup requires atomic never-authorized START fence")
	}
	return validatePreparationSettlement(observed)
}

func preparationUnitHistory(ctx context.Context, tx *sql.Tx, job string) ([]ProvisionRecord, error) {
	rows, err := tx.QueryContext(ctx, "SELECT record FROM provisioning_ledger WHERE kind='unit' ORDER BY rowid")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var history []ProvisionRecord
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var record ProvisionRecord
		if err = decodeProvisionRecord(raw, &record); err != nil {
			return nil, err
		}
		var desired ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); err != nil {
			return nil, err
		}
		if desired.Source == job && preparationUnitName(record.Identity) {
			history = append(history, record)
		}
	}
	return history, rows.Err()
}

func samePreparationSpace(left, right ImageSpace) bool {
	return left.JobID == right.JobID && left.ProvisionID == right.ProvisionID && left.ReusedSource == right.ReusedSource && left.SourceGenerationID == right.SourceGenerationID &&
		left.Source == right.Source && left.Cache == right.Cache && left.Work == right.Work && left.SourceProject == right.SourceProject && left.CacheProject == right.CacheProject && left.WorkProject == right.WorkProject
}

func (s *Store) requirePreparationWriterHistory(ctx context.Context, tx *sql.Tx, space ImageSpace, originalAcquisition bool) error {
	history, err := preparationUnitHistory(ctx, tx, space.JobID)
	if err != nil {
		return err
	}
	if len(history) == 0 {
		return errors.New("preparation has no original confined writer history")
	}
	hasAcquisition := false
	for _, record := range history {
		if record.State != "OBSERVED" {
			return errors.New("preparation has uncertain helper history")
		}
		var outer ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &outer); err != nil {
			return err
		}
		if outer.Writer == nil || !outer.Writer.StartIntent || outer.Writer.StartForbidden {
			return errors.New("preparation lacks immutable current-protocol START evidence")
		}
		if err = s.validatePreparationScope(ctx, tx, record, outer, true); err != nil {
			return err
		}
		if outer.Writer.Launch.JobID != space.JobID || outer.Writer.Launch.ProvisionID != space.ProvisionID {
			return errors.New("preparation helper belongs to a different native space")
		}
		hasAcquisition = hasAcquisition || outer.Writer.Launch.Purpose == gvxstage.PreparationPurpose
		if err = validatePreparationSettlement(outer); err != nil {
			return err
		}
		internal, err := readPreparationProvision(ctx, tx, "systemd-"+outer.Writer.Launch.Generation)
		if err != nil {
			return err
		}
		var captured ProvisionProperties
		if internal.State != "OBSERVED" {
			return errors.New("preparation internal invocation was never observed")
		}
		if err = gvxcontract.DecodeStrict(internal.Observed.Attributes, 64<<10, 16, &captured); err != nil {
			return err
		}
		if !preparationWriterPrefix(outer.Writer, captured.Writer) || !preparationWriterPrefix(captured.Writer, outer.Writer) {
			return errors.New("outer preparation dropped original internal confinement evidence")
		}
		if err = s.validatePreparationScope(ctx, tx, internal, captured, true); err != nil {
			return err
		}
		if err = validatePreparationSettlement(captured); err != nil {
			return err
		}
	}
	if originalAcquisition && !hasAcquisition {
		return errors.New("new loader cannot substitute for original source acquisition proof")
	}
	return nil
}

func (s *Store) requireOriginalPreparationSource(ctx context.Context, tx *sql.Tx, space ImageSpace) error {
	sourceJob := filepath.Base(space.Source)
	rows, err := tx.QueryContext(ctx, "SELECT record FROM provisioning_ledger WHERE kind='image' AND identity=?", "image-space:"+sourceJob)
	if err != nil {
		return err
	}
	var originals []ProvisionRecord
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		var record ProvisionRecord
		if err = decodeProvisionRecord(raw, &record); err != nil {
			rows.Close()
			return err
		}
		originals = append(originals, record)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(originals) != 1 {
		return errors.New("reused preparation source lacks unique original acquisition space")
	}
	originalRecord, original, err := preparationSpaceRecord(ctx, tx, originals[0].ID)
	if err != nil {
		return err
	}
	if originalRecord.State != "OBSERVED" || !original.Committed || original.ReusedSource || original.Source != space.Source || original.SourceProject != space.SourceProject {
		return errors.New("reused preparation source lacks genuinely committed original provenance")
	}
	rows, err = tx.QueryContext(ctx, "SELECT record FROM provisioning_ledger WHERE kind='image' AND identity=?", sourceJob)
	if err != nil {
		return err
	}
	found := false
	var imageID string
	var originalInput provision.ApprovedImageInput
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		var acquisition ProvisionRecord
		if err = decodeProvisionRecord(raw, &acquisition); err != nil {
			rows.Close()
			return err
		}
		var desired, observed ProvisionProperties
		if err = gvxcontract.DecodeStrict(acquisition.Desired, 64<<10, 16, &desired); err != nil {
			rows.Close()
			return err
		}
		if acquisition.State != "OBSERVED" || desired.ApprovedImageInput == nil || !acquisition.ProductCreated || acquisition.ExistedBefore {
			rows.Close()
			return errors.New("reused source lacks original authenticated acquisition")
		}
		if err = gvxcontract.DecodeStrict(acquisition.Observed.Attributes, 64<<10, 16, &observed); err != nil {
			rows.Close()
			return err
		}
		if desired.ImageSpace == nil || observed.ImageSpace == nil || !samePreparationSpace(*desired.ImageSpace, original) || !samePreparationSpace(*observed.ImageSpace, original) ||
			desired.ApprovedImageInput.JobID != sourceJob || observed.ApprovedImageInput == nil || *observed.ApprovedImageInput != *desired.ApprovedImageInput || !provision.ValidDigest(observed.Digest) {
			rows.Close()
			return errors.New("reused source changed original acquisition binding")
		}
		if err = validateImageAcquisitionProperties(desired); err != nil {
			rows.Close()
			return err
		}
		if found && (imageID != observed.Digest || originalInput != *desired.ApprovedImageInput) {
			rows.Close()
			return errors.New("original acquisition has conflicting immutable image provenance")
		}
		imageID, originalInput = observed.Digest, *desired.ApprovedImageInput
		found = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if !found {
		return errors.New("reused source has no original acquisition record")
	}
	var imageRaw []byte
	if err = tx.QueryRowContext(ctx, "SELECT record FROM image_records WHERE id=?", imageID).Scan(&imageRaw); err != nil {
		return err
	}
	var image provision.ImageRecord
	if err = gvxcontract.DecodeStrict(imageRaw, durableJSONMax, 32, &image); err != nil {
		return err
	}
	if image.ID != imageID || image.Revision != provision.Revision(originalInput) || image.SourceKind != originalInput.SourceKind || image.SourceRef != originalInput.SourceRef ||
		originalInput.SourceKind != "registry" && image.SourceDigest != originalInput.ArchiveDigest {
		return errors.New("reused source immutable image differs from original authenticated acquisition")
	}
	return s.requirePreparationWriterHistory(ctx, tx, original, true)
}

func (s *Store) requirePreparationWriterDomain(ctx context.Context, space ImageSpace) error {
	if !safeID(space.JobID) || !safeID(space.ProvisionID) {
		return invalid("preparation proof requires exact job and provision IDs")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, actual, err := preparationSpaceRecord(ctx, tx, space.ProvisionID)
	if err != nil {
		return err
	}
	if !samePreparationSpace(actual, space) {
		return errors.New("preparation proof refers to a different journaled space")
	}
	if err = s.requirePreparationWriterHistory(ctx, tx, actual, false); err != nil {
		return err
	}
	if actual.ReusedSource {
		if err = s.requireOriginalPreparationSource(ctx, tx, actual); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RequirePreparationWriterDomain checks persisted finite-writer closure only.
// Future storage publication, Work zero and COMPLETE are deliberately independent.
func (s *Store) RequirePreparationWriterDomain(ctx context.Context, space ImageSpace) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	return s.requirePreparationWriterDomain(ctx, space)
}

func (r *MetadataReader) RequirePreparationWriterDomain(ctx context.Context, space ImageSpace) error {
	if r == nil || r.store == nil {
		return ErrManagementGuardRequired
	}
	if err := r.store.gate.require(false); err != nil {
		return err
	}
	return r.store.requirePreparationWriterDomain(ctx, space)
}

// Exact 104-byte little-endian sock_filter identity from stage's original
// filter-v1 snapshot 0984. Unsupported history is never execution authority.
const preparationUnsupportedFilterV1Digest = "sha256:0346bf09d9d0fdbcd03c4744468425b0f66225d81770b00f0515d5e7fc89eddd"

// Caller must additionally require exact COMPLETE original outer/internal
// records. This validator is only for immutable quarantine/full-disposal facts.
func validateUnsupportedPreparationWriterV1(properties ProvisionProperties) error {
	if properties.Writer == nil || properties.Writer.Birth == nil || properties.Writer.Evidence == nil || !properties.Writer.StartIntent || properties.Writer.StartForbidden {
		return errors.New("unsupported filter history lacks original full START evidence")
	}
	if err := validatePreparationWriterPropertiesFilter(properties, 1, preparationUnsupportedFilterV1Digest); err != nil {
		return err
	}
	return validateStoredPreparationSettlement(properties)
}

// validateCompletePreparationV1Record qualifies both halves of an immutable
// historical row before reusing field-shape checks without current admission.
func validateCompletePreparationV1Record(record ProvisionRecord, product string) (ProvisionProperties, error) {
	var desired, observed ProvisionProperties
	if record.Kind != "unit" || !preparationUnitName(record.Identity) || record.State != "OBSERVED" || record.CleanupState != "COMPLETE" ||
		!record.ProductCreated || record.ExistedBefore || record.Observed.Identity != record.Identity {
		return observed, errors.New("unsupported preparation history is not exact completed owned unit history")
	}
	if err := gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); err != nil {
		return observed, err
	}
	if err := gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &observed); err != nil {
		return observed, err
	}
	if err := validateUnsupportedPreparationWriterV1(observed); err != nil {
		return observed, err
	}
	launch := observed.Writer.Launch
	if launch.InstallationID != product || record.Identity != launch.UnitName || desired.Name != launch.UnitName ||
		desired.Unit == nil || desired.Unit.Name != launch.UnitName || desired.Unit.Generation != launch.Generation || desired.Unit.BootID != launch.BootID ||
		desired.Limits == nil || observed.Limits == nil || *desired.Limits != *observed.Limits || desired.Source != observed.Source ||
		desired.Absence != nil || desired.Exit != nil || desired.Rejection != "" || observed.Rejection != "" {
		return observed, errors.New("unsupported preparation changed its original dispatch binding")
	}
	if len(desired.TransportPipes) != 0 && !slices.Equal(desired.TransportPipes, observed.TransportPipes) {
		return observed, errors.New("unsupported preparation changed its original transport identities")
	}
	if desired.Writer != nil {
		if desired.Writer.Launch != launch || desired.Writer.Birth != nil || desired.Writer.Evidence != nil || desired.Writer.StartIntent || desired.Writer.StartForbidden {
			return observed, errors.New("unsupported preparation lacks exact immutable launch-only intent")
		}
		if err := validatePreparationWriterPropertiesFilter(desired, 1, preparationUnsupportedFilterV1Digest); err != nil {
			return observed, err
		}
	}
	if record.ID == "systemd-"+launch.Generation {
		if desired.Writer == nil || observed.Source != preparationProgram(launch.Purpose) {
			return observed, errors.New("unsupported internal preparation lacks original pre-dispatch protocol intent")
		}
	} else if observed.Source != launch.JobID {
		return observed, errors.New("unsupported outer preparation belongs to a different original job")
	}
	if err := validProvisionShape(record.Kind, record.Desired, desired); err != nil {
		return observed, err
	}
	if err := validProvisionShape(record.Kind, record.Observed.Attributes, observed); err != nil {
		return observed, err
	}
	return observed, nil
}

// This is a passive, exact COMPLETE-v1 exception to raw historical reads only.
// It never mutates/re-encodes either row or supplies current execution authority.
func (s *Store) validateUnsupportedPreparationHistory(ctx context.Context, record ProvisionRecord) error {
	observed, err := validateCompletePreparationV1Record(record, s.productID)
	if err != nil {
		return err
	}
	internalID := "systemd-" + observed.Writer.Launch.Generation
	if record.ID == internalID {
		return nil
	}
	var raw []byte
	if err = s.db.QueryRowContext(ctx, "SELECT record FROM provisioning_ledger WHERE id=?", internalID).Scan(&raw); err != nil {
		return err
	}
	var internal ProvisionRecord
	if err = decodeProvisionRecord(raw, &internal); err != nil {
		return err
	}
	if internal.ID != internalID {
		return errors.New("unsupported preparation companion identity mismatch")
	}
	captured, err := validateCompletePreparationV1Record(internal, s.productID)
	if err != nil {
		return err
	}
	if internal.Identity != record.Identity || !preparationWriterPrefix(observed.Writer, captured.Writer) || !preparationWriterPrefix(captured.Writer, observed.Writer) ||
		*observed.Unit != *captured.Unit || !equalProcessExit(observed.Exit, captured.Exit) || observed.JobPath != captured.JobPath ||
		!slices.Equal(observed.TransportPipes, captured.TransportPipes) || *observed.MountNamespace != *captured.MountNamespace ||
		observed.MountNamespaceDisposition != captured.MountNamespaceDisposition || observed.Absence.BootID != captured.Absence.BootID {
		return errors.New("unsupported outer preparation differs from exact completed internal history")
	}
	return nil
}
