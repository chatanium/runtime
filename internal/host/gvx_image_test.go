//go:build linux

package host

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/gvxstage"
	"github.com/thirdscam/chatanium/internal/provision"
)

func testImagePreparationStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	guard := testManagementGuard(t)
	database, err := os.OpenFile(filepath.Join(dir, "supervisor.sqlite"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := openStoreDB(ctx, dir, true, guard)
	if err != nil {
		t.Fatal(err)
	}
	store.productID = strings.Repeat("1", 32)
	if err = store.initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = store.AcquireLease(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.installationLease.Close(); _ = store.Close() })
	manifest := InstallationManifest{Format: "chatanium-gvx", FormatVersion: 1, SchemaVersion: 1, RuntimeInstallationID: store.productID, State: "READY", DesiredRunState: "STOPPED", BundleDigest: "sha256:" + strings.Repeat("a", 64), Paths: InstallationPaths{StorageRoot: filepath.Join(dir, "storage")}, Identities: ProductIdentities{Preparer: NumericIdentity{UID: 1001, GID: 1002}}, Budget: StorageBudget{SourceBytes: 1 << 20, SourceInodes: 1024, CacheBytes: 1 << 20, CacheInodes: 1024, PreparationBytes: 1 << 20, PreparationInodes: 1024}}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.db.ExecContext(ctx, "INSERT INTO runtime_installations VALUES(?,?)", store.productID, raw); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestGvxPreparationHelperLedgerCompletion(t *testing.T) {
	ctx := context.Background()
	store := testImagePreparationStore(t)
	var raw []byte
	var err error
	job := strings.Repeat("2", 32)
	generations := map[string]string{"source": "sha256:" + strings.Repeat("3", 64), "cache": "sha256:" + strings.Repeat("4", 64)}
	for kind, generation := range generations {
		if _, err = store.ReserveStorage(ctx, job+":"+kind, kind, 4096, 16); err != nil {
			t.Fatal(err)
		}
		if err = store.BindStorageGeneration(ctx, job+":"+kind, generation); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = store.ReserveStorage(ctx, job+":preparation", "preparation", 4096, 16); err != nil {
		t.Fatal(err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	proof := CleanupEvidence{BootID: strings.TrimSpace(string(boot)), JobsAbsent: true, ProcessesAbsent: true, TransportsClosed: true, MountsAbsent: true, OpenReferencesAbsent: true}
	ledgers := []string{strings.Repeat("5", 32), strings.Repeat("6", 32)}
	observations := make(map[string][]byte)
	manager := &ImageManager{store: store}
	for index, program := range []string{"preparer", "rungv"} {
		generation := ledgers[index]
		name := "chatanium-image-" + program + "-" + generation + ".service"
		proposed := UnitIdentity{Name: name, Generation: generation, BootID: proof.BootID}
		properties := ProvisionProperties{Name: name, Source: job, Unit: &proposed, Limits: &ResourceLimits{NanoCPUs: 1000000000, MemoryBytes: 128 << 20, Pids: 8}, ProductCreated: true}
		raw, err = json.Marshal(properties)
		if err != nil {
			t.Fatal(err)
		}
		if err = store.BeginProvision(ctx, ProvisionIntent{ID: generation, Kind: "unit", Identity: name, ProductCreated: true, Desired: raw}); err != nil {
			t.Fatal(err)
		}
		actual := proposed
		actual.InvocationID = strings.Repeat("7", 32)
		actual.CgroupPath = filepath.Join("/system.slice", name)
		actual.ExecutableDigest = "sha256:" + strings.Repeat("8", 64)
		actual.ResourceFingerprint = "sha256:" + strings.Repeat("9", 64)
		actual.MainPID = 100 + index
		actual.StartTime = uint64(1000 + index)
		launch := testImageWriterLaunch(t, store, job, proposed, program == "rungv")
		writer := testPreparationWriterRecord(t, launch, actual)
		internal := properties
		internal.Source = program
		internal.Writer = &PreparationWriterRecord{Launch: launch}
		internalID := "systemd-" + generation
		persist := func(id string, p ProvisionProperties) {
			t.Helper()
			attributes, e := json.Marshal(p)
			if e != nil {
				t.Fatal(e)
			}
			if e = store.ObserveProvision(ctx, id, ObjectObservation{Identity: name, Attributes: attributes}); e != nil {
				t.Fatal(e)
			}
		}
		raw, err = json.Marshal(internal)
		if err != nil {
			t.Fatal(err)
		}
		if err = store.BeginProvision(ctx, ProvisionIntent{ID: internalID, Kind: "unit", Identity: name, ProductCreated: true, Desired: raw}); err != nil {
			t.Fatal(err)
		}
		birth := writer
		birth.Evidence = nil
		birth.StartIntent = false
		internal.Unit = &actual
		internal.Writer = &birth
		internal.TransportPipes = []string{"pipe:[101]", "pipe:[102]", "pipe:[103]"}
		internal.MountNamespace = &writer.Birth.MountNamespace
		internal.MountNamespaceDisposition = NamespacePrivate
		persist(internalID, internal)
		internal.Writer = &writer
		persist(internalID, internal)
		properties.Unit = &actual
		properties.Exit = &ProcessExit{Kind: "exit", Value: 0}
		properties.CgroupEmpty = true
		if err = manager.capturePreparationNative(ctx, actual, &properties, false); err != nil {
			t.Fatal(err)
		}
		if !samePreparationWriter(properties.Writer, &writer) {
			t.Fatal("outer helper did not capture the exact internal writer record")
		}
		internal.Exit = properties.Exit
		internal.CgroupEmpty = true
		persist(internalID, internal)
		raw, err = json.Marshal(properties)
		if err != nil {
			t.Fatal(err)
		}
		if err = store.ObserveProvision(ctx, generation, ObjectObservation{Identity: name, Attributes: raw}); err != nil {
			t.Fatal(err)
		}
		helperProof := proof
		helperProof.Units = []UnitIdentity{actual}
		helperProof.Details, err = json.Marshal(UnitAbsenceDetails{UnitAbsent: true, CgroupEmpty: true, TransportPipes: properties.TransportPipes, WriterUserNamespace: &writer.Birth.UserNamespace, WriterUserNamespaceAbsent: true})
		if err != nil {
			t.Fatal(err)
		}
		internal.Absence = &helperProof
		persist(internalID, internal)
		properties.Absence = &helperProof
		persist(generation, properties)
		raw, err = json.Marshal(properties)
		if err != nil {
			t.Fatal(err)
		}
		observations[generation] = raw
		proof.Units = append(proof.Units, actual)
	}
	if err = store.AssertRemovable(ctx); err == nil {
		t.Fatal("uncompleted helper journals allowed stop/removal")
	}
	incomplete := proof
	incomplete.MountsAbsent = false
	if err = manager.completePreparationUnitLedgers(ctx, ledgers, incomplete); err == nil {
		t.Fatal("unknown helper namespace allowed journal retirement")
	}
	wrongInvocation := proof
	wrongInvocation.Units = proof.Units[1:]
	if err = manager.completePreparationUnitLedgers(ctx, ledgers[:1], wrongInvocation); err == nil {
		t.Fatal("another invocation retired the helper journal")
	}
	if err = manager.completePreparationUnitLedgers(ctx, ledgers[:1], proof); err != nil {
		t.Fatal(err)
	}
	if err = store.AssertRemovable(ctx); err == nil {
		t.Fatal("one helper completion retired another helper journal")
	}
	if err = manager.completePreparationUnitLedgers(ctx, ledgers[1:], proof); err != nil {
		t.Fatal(err)
	}
	if err = store.AssertRemovable(ctx); err != nil {
		t.Fatalf("completed helper journals still blocked stop/removal: %v", err)
	}
	history, err := store.PreparationUnitProvisions(ctx, job)
	if err != nil || len(history) != len(ledgers) {
		t.Fatalf("helper history lost: %d %v", len(history), err)
	}
	for _, record := range history {
		if record.CleanupState != "COMPLETE" || string(record.Observed.Attributes) != string(observations[record.ID]) {
			t.Fatal("completion rewrote original terminal or namespace evidence")
		}
		if err = store.ObserveProvision(ctx, record.ID, record.Observed); err == nil {
			t.Fatal("completed helper observation became mutable")
		}
	}
	for kind, generation := range generations {
		got, err := store.StorageGeneration(ctx, job+":"+kind)
		if err != nil || got != generation {
			t.Fatalf("unit retirement reclaimed retained %s generation: %s %v", kind, got, err)
		}
	}
}

func TestGvxPublicationRejectsMissingWriterDomain(t *testing.T) {
	ctx := context.Background()
	store := testImagePreparationStore(t)
	space := ImageSpace{JobID: strings.Repeat("2", 32), ProvisionID: strings.Repeat("3", 32)}
	expected := store.RequirePreparationWriterDomain(ctx, space)
	if expected == nil {
		t.Fatal("missing helper history acquired writer authority")
	}
	manager := &ImageManager{store: store}
	if _, err := manager.publish(ctx, space, provision.ImageRecord{}, provision.PrepareLimits{}); err == nil || err.Error() != expected.Error() {
		t.Fatalf("cache publication bypassed writer-domain barrier: %v", err)
	}
	if _, err := manager.publishDevelopmentWorker(ctx, space, bundle.DevelopmentWorkerManifest{}, provision.PrepareLimits{}); err == nil || err.Error() != expected.Error() {
		t.Fatalf("development publication bypassed writer-domain barrier: %v", err)
	}
}

func TestGvxCaptureRejectsLegacyNativeHistory(t *testing.T) {
	for _, cleanup := range []string{"PENDING", "COMPLETE"} {
		t.Run(cleanup, func(t *testing.T) {
			ctx := context.Background()
			store := testImagePreparationStore(t)
			generation := strings.Repeat("2", 32)
			unit := UnitIdentity{Name: "chatanium-image-preparer-" + generation + ".service", Generation: generation}
			properties := ProvisionProperties{Name: unit.Name, Unit: &unit, TransportPipes: []string{"pipe:[101]", "pipe:[102]", "pipe:[103]"}, MountNamespace: &NamespaceIdentity{Device: 4, Inode: 200}, MountNamespaceDisposition: NamespacePrivate}
			attributes, err := json.Marshal(properties)
			if err != nil {
				t.Fatal(err)
			}
			record := ProvisionRecord{ProvisionIntent: ProvisionIntent{ID: "systemd-" + generation, Kind: "unit", Identity: unit.Name, Desired: attributes}, State: "OBSERVED", CleanupState: cleanup, Observed: ObjectObservation{Identity: unit.Name, Attributes: attributes}}
			raw, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = store.db.ExecContext(ctx, "INSERT INTO provisioning_ledger VALUES(?,?,?,?)", record.ID, record.Kind, record.Identity, raw); err != nil {
				t.Fatal(err)
			}
			manager := &ImageManager{store: store}
			outer := ProvisionProperties{Source: strings.Repeat("3", 32)}
			if err = manager.capturePreparationNative(ctx, unit, &outer, false); err == nil {
				t.Fatal("legacy native history acquired current writer authority")
			}
			err = manager.capturePreparationNative(ctx, unit, &outer, true)
			if cleanup == "COMPLETE" && err != nil {
				t.Fatalf("immutable legacy native cleanup capture was blocked: %v", err)
			}
			if cleanup != "COMPLETE" && err == nil {
				t.Fatal("pending legacy helper bypassed current native history requirements")
			}
			if outer.Writer != nil {
				t.Fatal("cleanup capture manufactured legacy writer authority")
			}
			unchanged, err := store.Provision(ctx, record.ID)
			if err != nil || string(unchanged.Observed.Attributes) != string(attributes) || unchanged.CleanupState != cleanup {
				t.Fatalf("legacy cleanup capture rewrote native history: %v", err)
			}
		})
	}
}

func testImageWriterLaunch(t *testing.T, store *Store, job string, unit UnitIdentity, load bool) PreparationWriterLaunch {
	t.Helper()
	installation, err := store.Installation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	projects := make(map[string]uint32)
	for _, kind := range []string{"source", "cache", "preparation"} {
		project, exists, e := store.StorageProject(context.Background(), job+":"+kind)
		if e != nil || !exists {
			t.Fatalf("missing fixture %s project: %v", kind, e)
		}
		projects[kind] = project
	}
	root := installation.Paths.StorageRoot
	sourcePool := NativeRootIdentity{RootID: "source-barrier", HostPath: filepath.Join(root, "images"), Dev: 1, Ino: 100, Mode: 0700}
	workPool := NativeRootIdentity{RootID: "work-barrier", HostPath: filepath.Join(root, "preparation"), Dev: 1, Ino: 101, Mode: 0700}
	cache := NativeRootIdentity{RootID: "cache-barrier", HostPath: filepath.Join(root, "prepared", job), Dev: 1, Ino: 102, Mode: 0700, Project: projects["cache"]}
	source := NativeRootIdentity{RootID: "source", HostPath: filepath.Join(sourcePool.HostPath, job), Dev: 1, Ino: 103, UID: 1001, GID: 1002, Mode: 0700, Project: projects["source"]}
	work := NativeRootIdentity{RootID: "work", HostPath: filepath.Join(workPool.HostPath, job), Dev: 1, Ino: 104, UID: 1001, GID: 1002, Mode: 0700, Project: projects["preparation"]}
	generation := NativeRootIdentity{RootID: "cache", HostPath: filepath.Join(cache.HostPath, "generation"), Dev: 1, Ino: 105, UID: 1001, GID: 1002, Mode: 0700, Project: projects["cache"]}
	purpose := gvxstage.PreparationPurpose
	if load {
		purpose = gvxstage.LoadPurpose
		source.UID, source.Mode = 0, 0550
	}
	layout := PreparationStorageView{Version: gvxcontract.PreparationWriterDomainVersion, JobID: job, ProvisionID: strings.Repeat("b", 32), Source: PreparationStorageRoot{Barrier: sourcePool, Data: source, ReadOnly: load}, Cache: PreparationStorageRoot{Barrier: cache, Data: generation}, Work: PreparationStorageRoot{Barrier: workPool, Data: work}}
	if !load {
		space := ImageSpace{JobID: job, ProvisionID: layout.ProvisionID, Source: source.HostPath, Cache: cache.HostPath, Work: work.HostPath, SourceProject: source.Project, CacheProject: cache.Project, WorkProject: work.Project}
		raw, e := json.Marshal(ProvisionProperties{Name: "image-space", ImageSpace: &space, ProductCreated: true})
		if e != nil {
			t.Fatal(e)
		}
		if e = store.BeginProvision(context.Background(), ProvisionIntent{ID: space.ProvisionID, Kind: "image", Identity: "image-space:" + job, ProductCreated: true, Desired: raw}); e != nil {
			t.Fatal(e)
		}
	}
	digest := "sha256:" + strings.Repeat("8", 64)
	return PreparationWriterLaunch{Version: gvxcontract.PreparationWriterDomainVersion, ProtocolVersion: gvxcontract.PreparationWriterProtocolVersion, FilterVersion: gvxcontract.PreparationWriterFilterVersion, InstallationID: store.productID, JobID: job, ProvisionID: layout.ProvisionID, UnitName: unit.Name, Generation: unit.Generation, BootID: unit.BootID, Purpose: purpose, BundleDigest: installation.BundleDigest, StageDigest: digest, TargetDigest: digest, StagePath: preparationBase + "/gvx-stage", TargetPath: preparationBase + "/target", ArgumentDigest: digest, DeclarationDigest: digest, PreparerUID: 1001, PreparerGID: 1002, Layout: layout}
}

func TestGvxQuarantinedRecoverySkipsOnlyRetainedAdmission(t *testing.T) {
	ctx := context.Background()
	fixture := newLegacyQuarantineFixture(t)
	manager := &ImageManager{store: fixture.Store, storage: &Storage{store: fixture.Store}}
	installation, err := fixture.Store.Installation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	manager.storage.config.StorageRoot = installation.Paths.StorageRoot
	manager.cfg.Bundle.Digest = installation.BundleDigest
	history, err := fixture.Store.ObjectProvisions(ctx, "image", fixture.Space.JobID)
	if err != nil || len(history) != 1 {
		t.Fatalf("missing original acquisition fixture: %v", err)
	}
	var desired ProvisionProperties
	if err = json.Unmarshal(history[0].Desired, &desired); err != nil {
		t.Fatal(err)
	}
	if desired.PrepareLimits == nil || desired.ApprovedImageInput == nil {
		t.Fatal("quarantine fixture lacks original bounded approval")
	}
	manager.cfg.Limits = *desired.PrepareLimits
	if err = manager.requirePreparationUse(ctx, "image", fixture.Space); err == nil || !strings.Contains(err.Error(), "quarantined") {
		t.Fatalf("quarantined acquisition retained use authority: %v", err)
	}
	if _, _, found, err := manager.preparedImage(ctx, *desired.ApprovedImageInput); err == nil || found {
		t.Fatalf("quarantined original acquisition remained replayable: %v", err)
	}
	// The fixture has no native data tree: success here can only come from the
	// exact quarantined retained-admission skip, not legacy proof backfill.
	if err = manager.recover(ctx); err != nil {
		t.Fatalf("quarantined retained admission blocked recovery: %v", err)
	}
	job, provisionID, generation := newID(), newID(), newID()
	space := ImageSpace{JobID: job, ProvisionID: provisionID, Source: filepath.Join(installation.Paths.StorageRoot, "images", job), Cache: filepath.Join(installation.Paths.StorageRoot, "prepared", job), Work: filepath.Join(installation.Paths.StorageRoot, "preparation", job)}
	pending := ProvisionProperties{Name: job, ImageSpace: &space, PrepareLimits: desired.PrepareLimits, Revision: installation.BundleDigest, ProductCreated: true}
	raw, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	if err = fixture.Store.BeginProvision(ctx, ProvisionIntent{ID: newID(), Kind: "image", Identity: job, ProductCreated: true, Desired: raw}); err != nil {
		t.Fatal(err)
	}
	name := "chatanium-image-preparer-" + generation + ".service"
	unit := UnitIdentity{Name: name, Generation: generation, BootID: "test-boot"}
	helper := ProvisionProperties{Name: name, Source: job, Unit: &unit, Limits: &ResourceLimits{NanoCPUs: manager.cfg.Limits.NanoCPUs, MemoryBytes: manager.cfg.Limits.MemoryBytes, Pids: manager.cfg.Limits.Tasks}, ProductCreated: true}
	raw, err = json.Marshal(helper)
	if err != nil {
		t.Fatal(err)
	}
	ledger := newID()
	if err = fixture.Store.BeginProvision(ctx, ProvisionIntent{ID: ledger, Kind: "unit", Identity: name, ProductCreated: true, Desired: raw}); err != nil {
		t.Fatal(err)
	}
	unit.InvocationID = strings.Repeat("8", 32)
	unit.CgroupPath = "/system.slice/" + name
	unit.ExecutableDigest = "sha256:" + strings.Repeat("7", 64)
	unit.ResourceFingerprint = "sha256:" + strings.Repeat("6", 64)
	unit.MainPID, unit.StartTime = 200, 1
	raw, err = json.Marshal(helper)
	if err != nil {
		t.Fatal(err)
	}
	if err = fixture.Store.ObserveProvision(ctx, ledger, ObjectObservation{Identity: name, Attributes: raw}); err != nil {
		t.Fatal(err)
	}
	if err = manager.recover(ctx); err == nil {
		t.Fatal("quarantine skipped an unrelated uncertain helper")
	}
}

func TestGvxCapturePreservesUnsupportedCompletedWriter(t *testing.T) {
	ctx := context.Background()
	store := testImagePreparationStore(t)
	job, generation := newID(), newID()
	for _, kind := range []string{"source", "cache", "preparation"} {
		if _, err := store.ReserveStorage(ctx, job+":"+kind, kind, 4096, 16); err != nil {
			t.Fatal(err)
		}
	}
	unit := UnitIdentity{Name: "chatanium-image-preparer-" + generation + ".service", Generation: generation, BootID: "old-boot", InvocationID: newID(), CgroupPath: "/system.slice/legacy", ExecutableDigest: "sha256:" + strings.Repeat("8", 64), ResourceFingerprint: "sha256:" + strings.Repeat("9", 64), MainPID: 100, StartTime: 1000}
	launch := testImageWriterLaunch(t, store, job, unit, false)
	writer := testPreparationWriterRecord(t, launch, unit)
	launch.FilterVersion = 0
	writer.Launch = launch
	// Represent a persisted unsupported receipt; it is never revalidated or
	// relabeled as current confinement by cleanup identity capture.
	writer.Evidence.FilterVersion = 1
	writer.Evidence.FilterDigest = preparationUnsupportedFilterV1Digest
	if err := validatePreparationWriter(writer); err == nil {
		t.Fatal("unsupported historical filter became current writer authority")
	}
	properties := ProvisionProperties{Name: unit.Name, Source: "preparer", Unit: &unit, Limits: &ResourceLimits{NanoCPUs: 1000000000, MemoryBytes: 128 << 20, Pids: 8}, Writer: &writer, Exit: &ProcessExit{Kind: "exit", Value: 0}, CgroupEmpty: true, TransportPipes: []string{"pipe:[101]", "pipe:[102]", "pipe:[103]"}, MountNamespace: &writer.Birth.MountNamespace, MountNamespaceDisposition: NamespacePrivate, ProductCreated: true}
	nativeDetails, err := json.Marshal(UnitAbsenceDetails{UnitAbsent: true, CgroupEmpty: true, TransportPipes: properties.TransportPipes, WriterUserNamespace: &writer.Birth.UserNamespace, WriterUserNamespaceAbsent: true})
	if err != nil {
		t.Fatal(err)
	}
	historical := CleanupEvidence{BootID: unit.BootID, Units: []UnitIdentity{unit}, JobsAbsent: true, ProcessesAbsent: true, TransportsClosed: true, MountsAbsent: true, OpenReferencesAbsent: true, Details: nativeDetails}
	properties.Absence = &historical
	desired := properties
	desired.Writer = &PreparationWriterRecord{Launch: launch}
	desired.Exit = nil
	desired.CgroupEmpty = false
	desired.Absence = nil
	attributes, err := json.Marshal(properties)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}
	record := ProvisionRecord{ProvisionIntent: ProvisionIntent{ID: "systemd-" + generation, Kind: "unit", Identity: unit.Name, ProductCreated: true, Desired: intent}, State: "OBSERVED", CleanupState: "COMPLETE", Observed: ObjectObservation{Identity: unit.Name, Attributes: attributes}}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.db.ExecContext(ctx, "INSERT INTO provisioning_ledger VALUES(?,?,?,?)", record.ID, record.Kind, record.Identity, raw); err != nil {
		t.Fatal(err)
	}
	manager := &ImageManager{store: store}
	outer := properties
	outer.Source = job
	outerDesired := desired
	outerDesired.Source = job
	outerDesired.Writer = nil
	outerAttributes, err := json.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	outerIntent, err := json.Marshal(outerDesired)
	if err != nil {
		t.Fatal(err)
	}
	outerRecord := ProvisionRecord{ProvisionIntent: ProvisionIntent{ID: newID(), Kind: "unit", Identity: unit.Name, ProductCreated: true, Desired: outerIntent}, State: "OBSERVED", CleanupState: "COMPLETE", Observed: ObjectObservation{Identity: unit.Name, Attributes: outerAttributes}}
	outerRaw, err := json.Marshal(outerRecord)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.db.ExecContext(ctx, "INSERT INTO provisioning_ledger VALUES(?,?,?,?)", outerRecord.ID, outerRecord.Kind, outerRecord.Identity, outerRaw); err != nil {
		t.Fatal(err)
	}
	if err = manager.capturePreparationNative(ctx, unit, &outer, false); err == nil {
		t.Fatal("unsupported historical receipt passed current capture")
	}
	if err = manager.capturePreparationNative(ctx, unit, &outer, true); err != nil {
		t.Fatalf("immutable unsupported cleanup capture was blocked: %v", err)
	}
	if !samePreparationWriter(outer.Writer, &writer) {
		t.Fatal("cleanup capture replaced unsupported historical writer evidence")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	cleanup := historical
	cleanup.BootID = strings.TrimSpace(string(boot))
	if err = manager.completePreparationUnitLedgers(ctx, []string{outerRecord.ID}, cleanup); err != nil {
		t.Fatalf("already-COMPLETE historical helper completion was blocked: %v", err)
	}
	var unchanged []byte
	err = store.db.QueryRowContext(ctx, "SELECT record FROM provisioning_ledger WHERE id=?", record.ID).Scan(&unchanged)
	if err != nil || !bytes.Equal(unchanged, raw) {
		t.Fatalf("unsupported COMPLETE history was backfilled: %v", err)
	}
	err = store.db.QueryRowContext(ctx, "SELECT record FROM provisioning_ledger WHERE id=?", outerRecord.ID).Scan(&unchanged)
	if err != nil || !bytes.Equal(unchanged, outerRaw) {
		t.Fatalf("unsupported COMPLETE outer helper history was backfilled: %v", err)
	}
}
