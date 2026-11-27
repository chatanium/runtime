//go:build linux

package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/gvxstage"
	"github.com/thirdscam/chatanium/internal/provision"
	"golang.org/x/sys/unix"
)

func testPreparationWriterRecord(t *testing.T, launch PreparationWriterLaunch, unit UnitIdentity) PreparationWriterRecord {
	t.Helper()
	tasks := PreparationTaskSnapshot{ThreadCount: 1, SnapshotDigest: provision.DomainDigest("test-preparation-native-birth", []byte(unit.InvocationID)), SupplementaryGID: launch.PreparerGID, SupplementaryGroupCount: 1, NoNewPrivileges: true, SeccompMode: 2, SeccompFilters: 1}
	for index := range tasks.UIDs {
		tasks.UIDs[index] = launch.PreparerUID
		tasks.GIDs[index] = launch.PreparerGID
	}
	birth := PreparationWriterBirth{Version: gvxcontract.PreparationWriterDomainVersion, Unit: unit, PeerPID: unit.MainPID, PeerUID: launch.PreparerUID, PeerGID: launch.PreparerGID, PIDFDDevice: 16, PIDFDInode: 91,
		UserNamespace: NamespaceIdentity{Device: 4, Inode: 103}, ParentUserNamespace: NamespaceIdentity{Device: 4, Inode: 101}, HostUserNamespace: NamespaceIdentity{Device: 4, Inode: 101}, UserNamespaceType: unix.CLONE_NEWUSER, SetgroupsDenied: true,
		UIDMap: [2]PreparationIDMap{{Inside: 0, Outside: 0, Length: 1}, {Inside: launch.PreparerUID, Outside: launch.PreparerUID, Length: 1}}, GIDMap: [2]PreparationIDMap{{Inside: 0, Outside: 0, Length: 1}, {Inside: launch.PreparerGID, Outside: launch.PreparerGID, Length: 1}}, MountNamespace: NamespaceIdentity{Device: 4, Inode: 102}, Tasks: tasks}
	filtered := tasks
	filtered.SeccompFilters++
	filtered.SnapshotDigest = provision.DomainDigest("test-preparation-native-filtered", []byte(unit.InvocationID))
	evidence := PreparationWriterEvidence{Version: gvxcontract.PreparationWriterDomainVersion, ProtocolVersion: gvxcontract.PreparationWriterProtocolVersion, FilterVersion: gvxcontract.PreparationWriterFilterVersion, FilterDigest: gvxstage.PreparationFilterDigest(), AuditArch: unix.AUDIT_ARCH_X86_64, RejectX32: true, TSYNC: true, FilterReady: true, Tasks: filtered}
	writer := PreparationWriterRecord{Launch: launch, Birth: &birth, Evidence: &evidence, StartIntent: true}
	if err := validatePreparationWriter(writer); err != nil {
		t.Fatalf("invalid current-protocol preparation fixture: %v", err)
	}
	return writer
}

type preparationWriterFixture struct {
	create                    *createStateFixture
	space                     ImageSpace
	writer                    PreparationWriterRecord
	internal, outer           string
	internalBirth, outerBirth ProvisionProperties
}

func writerTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writerTestWithoutFilterIntent(t *testing.T, properties ProvisionProperties) []byte {
	t.Helper()
	var fields, writer, launch map[string]json.RawMessage
	if err := json.Unmarshal(writerTestJSON(t, properties), &fields); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fields["writer"], &writer); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(writer["launch"], &launch); err != nil {
		t.Fatal(err)
	}
	delete(launch, "filter_version")
	writer["launch"] = writerTestJSON(t, launch)
	fields["writer"] = writerTestJSON(t, writer)
	return writerTestJSON(t, fields)
}

func newPreparationWriterFixture(t *testing.T) *preparationWriterFixture {
	t.Helper()
	ctx := context.Background()
	create := newCreateStateFixture(t, EgressNone)
	store := create.journal
	manifest, err := store.Installation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	manifest.BundleDigest = "sha256:" + strings.Repeat("1", 64)
	manifest.Identities.Preparer = NumericIdentity{Name: "fixture-preparer", UID: 1001, GID: 1002}
	manifest.Paths.StorageRoot = filepath.Join(create.directory, "storage")
	if _, err = store.db.ExecContext(ctx, "UPDATE runtime_installations SET manifest=? WHERE id=?", writerTestJSON(t, manifest), store.productID); err != nil {
		t.Fatal(err)
	}
	job, spaceID, generation := strings.Repeat("c", 32), strings.Repeat("d", 32), strings.Repeat("e", 32)
	space := ImageSpace{JobID: job, ProvisionID: spaceID, Source: filepath.Join(manifest.Paths.StorageRoot, "images", job), Cache: filepath.Join(manifest.Paths.StorageRoot, "prepared", job), Work: filepath.Join(manifest.Paths.StorageRoot, "preparation", job), SourceProject: 71, CacheProject: 72, WorkProject: 73}
	spaceProperties := ProvisionProperties{Name: "image-space", ImageSpace: &space, ProductCreated: true}
	if err = store.BeginProvision(ctx, ProvisionIntent{ID: spaceID, Kind: "image", Identity: "image-space:" + job, ProductCreated: true, Desired: writerTestJSON(t, spaceProperties)}); err != nil {
		t.Fatal(err)
	}
	if err = store.ObserveProvision(ctx, spaceID, ObjectObservation{Identity: "image-space:" + job, Attributes: writerTestJSON(t, spaceProperties)}); err != nil {
		t.Fatal(err)
	}
	barrier := func(id, path string, ino uint64, project uint32) NativeRootIdentity {
		return NativeRootIdentity{RootID: id, HostPath: path, Dev: 19, Ino: ino, Mode: 0700, Project: project}
	}
	data := func(id, path string, ino uint64, project uint32) NativeRootIdentity {
		root := barrier(id, path, ino, project)
		root.UID = 1001
		root.GID = 1002
		return root
	}
	layout := PreparationStorageView{Version: gvxcontract.PreparationWriterDomainVersion, JobID: job, ProvisionID: spaceID,
		Source: PreparationStorageRoot{Barrier: barrier("source-pool", filepath.Dir(space.Source), 10, 0), Data: data("source", space.Source, 11, space.SourceProject)},
		Cache:  PreparationStorageRoot{Barrier: barrier("cache-envelope", space.Cache, 12, space.CacheProject), Data: data("cache", filepath.Join(space.Cache, "generation"), 13, space.CacheProject)},
		Work:   PreparationStorageRoot{Barrier: barrier("work-pool", filepath.Dir(space.Work), 14, 0), Data: data("work", space.Work, 15, space.WorkProject)}}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	name := "chatanium-image-preparer-" + generation + ".service"
	launch := PreparationWriterLaunch{Version: gvxcontract.PreparationWriterDomainVersion, ProtocolVersion: gvxcontract.PreparationWriterProtocolVersion, InstallationID: store.productID, JobID: job, ProvisionID: spaceID, UnitName: name, Generation: generation, BootID: strings.TrimSpace(string(boot)), Purpose: gvxstage.PreparationPurpose, BundleDigest: manifest.BundleDigest, StageDigest: "sha256:" + strings.Repeat("2", 64), TargetDigest: "sha256:" + strings.Repeat("3", 64), StagePath: "/chatanium/base/bin/gvx-stage", TargetPath: "/chatanium/base/bin/gvx-preparer", ArgumentDigest: "sha256:" + strings.Repeat("4", 64), DeclarationDigest: "sha256:" + strings.Repeat("5", 64), PreparerUID: 1001, PreparerGID: 1002, Layout: layout}
	launch.FilterVersion = gvxcontract.PreparationWriterFilterVersion
	unit := UnitIdentity{Name: name, InvocationID: strings.Repeat("a", 32), Generation: generation, BootID: launch.BootID, CgroupPath: "/system.slice/" + name, ExecutableDigest: launch.StageDigest, ResourceFingerprint: "fixture-resources", MainPID: 23456, StartTime: 91}
	writer := testPreparationWriterRecord(t, launch, unit)
	limits := ResourceLimits{NanoCPUs: 1_000_000_000, MemoryBytes: 128 << 20, Pids: 64}
	proposed := UnitIdentity{Name: name, Generation: generation, BootID: launch.BootID}
	outerID := strings.Repeat("f", 32)
	outer := ProvisionProperties{Name: name, Source: job, Unit: &proposed, Limits: &limits, ProductCreated: true}
	if err = store.BeginProvision(ctx, ProvisionIntent{ID: outerID, Kind: "unit", Identity: name, ProductCreated: true, Desired: writerTestJSON(t, outer)}); err != nil {
		t.Fatal(err)
	}
	internalID := "systemd-" + generation
	internal := outer
	internal.Source = "preparer"
	internal.TransportPipes = []string{"pipe:[101]", "pipe:[102]", "pipe:[103]"}
	internal.Writer = &PreparationWriterRecord{Launch: launch}
	if err = store.BeginProvision(ctx, ProvisionIntent{ID: internalID, Kind: "unit", Identity: name, ProductCreated: true, Desired: writerTestJSON(t, internal)}); err != nil {
		t.Fatal(err)
	}
	internal.Unit = &unit
	internal.MountNamespace = &writer.Birth.MountNamespace
	internal.MountNamespaceDisposition = NamespacePrivate
	internal.JobPath = "/org/freedesktop/systemd1/job/71"
	internal.Writer = &PreparationWriterRecord{Launch: launch, Birth: writer.Birth}
	if err = store.ObserveProvision(ctx, internalID, ObjectObservation{Identity: name, Attributes: writerTestJSON(t, internal)}); err != nil {
		t.Fatal(err)
	}
	outer = internal
	outer.Source = job
	if err = store.ObserveProvision(ctx, outerID, ObjectObservation{Identity: name, Attributes: writerTestJSON(t, outer)}); err != nil {
		t.Fatal(err)
	}
	return &preparationWriterFixture{create: create, space: space, writer: writer, internal: internalID, outer: outerID, internalBirth: internal, outerBirth: outer}
}

func (f *preparationWriterFixture) observe(t *testing.T, id string, properties ProvisionProperties) error {
	t.Helper()
	return f.create.journal.ObserveProvision(context.Background(), id, ObjectObservation{Identity: f.writer.Launch.UnitName, Attributes: writerTestJSON(t, properties)})
}

func (f *preparationWriterFixture) settlement(t *testing.T) CleanupEvidence {
	t.Helper()
	details := UnitAbsenceDetails{UnitAbsent: true, CgroupEmpty: true, TransportPipes: f.internalBirth.TransportPipes, WriterUserNamespace: &f.writer.Birth.UserNamespace, WriterUserNamespaceAbsent: true}
	return CleanupEvidence{BootID: f.writer.Launch.BootID, Units: []UnitIdentity{f.writer.Birth.Unit}, JobsAbsent: true, ProcessesAbsent: true, TransportsClosed: true, MountsAbsent: true, OpenReferencesAbsent: true, Details: writerTestJSON(t, details)}
}

func (f *preparationWriterFixture) settleFull(t *testing.T) {
	t.Helper()
	internal := f.internalBirth
	internal.Writer = &f.writer
	if err := f.observe(t, f.internal, internal); err != nil {
		t.Fatal(err)
	}
	outer := f.outerBirth
	outer.Writer = &f.writer
	if err := f.observe(t, f.outer, outer); err != nil {
		t.Fatal(err)
	}
	proof := f.settlement(t)
	for _, entry := range []struct {
		id         string
		properties ProvisionProperties
	}{{f.internal, internal}, {f.outer, outer}} {
		properties := entry.properties
		properties.Exit = &ProcessExit{Kind: "exit"}
		if err := f.observe(t, entry.id, properties); err != nil {
			t.Fatal(err)
		}
		properties.CgroupEmpty = true
		properties.Absence = &proof
		if err := f.observe(t, entry.id, properties); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPreparationWriterRejectsInvalidNativeDomain(t *testing.T) {
	fixture := newPreparationWriterFixture(t)
	cases := []struct {
		name   string
		change func(*PreparationWriterRecord)
	}{
		{"host user namespace", func(w *PreparationWriterRecord) { w.Birth.UserNamespace = w.Birth.HostUserNamespace }},
		{"foreign owner", func(w *PreparationWriterRecord) { w.Birth.UserNamespaceOwnerUID = 1001 }},
		{"untrusted parent", func(w *PreparationWriterRecord) { w.Birth.ParentUserNamespace.Inode++ }},
		{"wrong map", func(w *PreparationWriterRecord) { w.Birth.UIDMap[1].Outside++ }},
		{"setgroups allowed", func(w *PreparationWriterRecord) { w.Birth.SetgroupsDenied = false }},
		{"external supplementary authority", func(w *PreparationWriterRecord) { w.Birth.Tasks.SupplementaryGID++ }},
		{"capability", func(w *PreparationWriterRecord) { w.Birth.Tasks.Capabilities[2] = 1 }},
		{"missing no new privileges", func(w *PreparationWriterRecord) { w.Birth.Tasks.NoNewPrivileges = false }},
		{"wrong pidfd birth", func(w *PreparationWriterRecord) { w.Birth.PeerPID++ }},
		{"legacy protocol", func(w *PreparationWriterRecord) { w.Launch.ProtocolVersion = 1 }},
		{"wrong filter", func(w *PreparationWriterRecord) { w.Evidence.FilterDigest = "sha256:" + strings.Repeat("9", 64) }},
		{"unchanged filter count", func(w *PreparationWriterRecord) { w.Evidence.Tasks.SeccompFilters = w.Birth.Tasks.SeccompFilters }},
		{"filter not synchronized", func(w *PreparationWriterRecord) { w.Evidence.TSYNC = false }},
		{"missing filter ready", func(w *PreparationWriterRecord) { w.Evidence.FilterReady = false }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			writer := fixture.writer
			birth, evidence := *writer.Birth, *writer.Evidence
			writer.Birth, writer.Evidence = &birth, &evidence
			test.change(&writer)
			if err := validatePreparationWriter(writer); err == nil {
				t.Fatal("invalid native confinement accepted")
			}
		})
	}
}

func TestPreparationWriterEvidenceAndStartAreAtomic(t *testing.T) {
	f := newPreparationWriterFixture(t)
	properties := f.internalBirth
	withoutStart := f.writer
	withoutStart.StartIntent = false
	properties.Writer = &withoutStart
	if err := f.observe(t, f.internal, properties); err == nil {
		t.Fatal("full evidence committed without START intent")
	}
	withoutEvidence := f.writer
	withoutEvidence.Evidence = nil
	properties.Writer = &withoutEvidence
	if err := f.observe(t, f.internal, properties); err == nil {
		t.Fatal("START committed without full evidence")
	}
	saved, err := f.create.journal.PreparationWriter(context.Background(), f.internal)
	if err != nil || saved.Evidence != nil || saved.StartIntent {
		t.Fatalf("failed admission partially persisted authority: %+v %v", saved, err)
	}
}

func TestPreparationWriterEagerTerminalMonotonicMerge(t *testing.T) {
	f := newPreparationWriterFixture(t)
	terminal := f.internalBirth
	terminal.Writer = nil
	terminal.Exit = &ProcessExit{Kind: "exit", Value: 7}
	if err := f.observe(t, f.internal, terminal); err != nil {
		t.Fatal(err)
	}
	full := f.internalBirth
	full.Writer = &f.writer
	if err := f.observe(t, f.internal, full); err != nil {
		t.Fatal(err)
	}
	// The eager observer still holds an earlier, launch-only copy.
	terminal.Writer = &PreparationWriterRecord{Launch: f.writer.Launch}
	if err := f.observe(t, f.internal, terminal); err != nil {
		t.Fatal(err)
	}
	record, err := f.create.journal.Provision(context.Background(), f.internal)
	if err != nil {
		t.Fatal(err)
	}
	var saved ProvisionProperties
	if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Writer == nil || !saved.Writer.StartIntent || saved.Writer.Evidence == nil || saved.Exit == nil || saved.Exit.Value != 7 {
		t.Fatalf("gate/native race dropped immutable prefix: %+v", saved)
	}
	changed := f.writer
	birth := *changed.Birth
	birth.UserNamespace.Inode++
	changed.Birth = &birth
	full.Writer = &changed
	if err = f.observe(t, f.internal, full); err == nil {
		t.Fatal("replacement native birth accepted")
	}
}

func TestPreparationWriterForbidFencesLateStartAndComplete(t *testing.T) {
	f := newPreparationWriterFixture(t)
	ctx := context.Background()
	wrong := *f.writer.Birth
	wrong.Unit.StartTime++
	if err := f.create.journal.ForbidPreparationWriterStart(ctx, f.internal, wrong); err == nil {
		t.Fatal("different native birth fenced")
	}
	if err := f.create.journal.ForbidPreparationWriterStart(ctx, f.internal, *f.writer.Birth); err != nil {
		t.Fatal(err)
	}
	full := f.internalBirth
	full.Writer = &f.writer
	if err := f.observe(t, f.internal, full); err == nil {
		t.Fatal("late START bypassed causal forbid fence")
	}
	proof := f.settlement(t)
	closed := f.internalBirth
	closed.Exit = &ProcessExit{Kind: "exit", Value: 1}
	if err := f.observe(t, f.internal, closed); err != nil {
		t.Fatal(err)
	}
	closed.Absence = &proof
	closed.CgroupEmpty = true
	if err := f.observe(t, f.internal, closed); err != nil {
		t.Fatal(err)
	}
	if err := f.create.journal.CompleteProvisionCleanup(ctx, f.internal, proof); err != nil {
		t.Fatal(err)
	}
	if err := f.observe(t, f.internal, full); err == nil {
		t.Fatal("COMPLETE history was backfilled")
	}
	saved, err := f.create.journal.PreparationWriter(ctx, f.internal)
	if err != nil || !saved.StartForbidden || saved.StartIntent || saved.Evidence != nil {
		t.Fatalf("never-authorized cleanup fabricated full proof: %+v %v", saved, err)
	}
	if err = f.create.journal.RequirePreparationWriterDomain(ctx, f.space); err == nil {
		t.Fatal("never-authorized cleanup promoted image readiness")
	}
}

func TestPreparationWriterRejectsOuterOnlyProof(t *testing.T) {
	f := newPreparationWriterFixture(t)
	outer := f.outerBirth
	outer.Writer = &f.writer
	if err := f.observe(t, f.outer, outer); err == nil {
		t.Fatal("outer-only START evidence accepted")
	}
	internal := f.internalBirth
	internal.Writer = &f.writer
	if err := f.observe(t, f.internal, internal); err != nil {
		t.Fatal(err)
	}
	if err := f.observe(t, f.outer, outer); err != nil {
		t.Fatal(err)
	}
}

func TestPreparationWriterClosurePrecedesStorageCommitAndComplete(t *testing.T) {
	f := newPreparationWriterFixture(t)
	ctx := context.Background()
	if err := f.create.journal.RequirePreparationWriterDomain(ctx, f.space); err == nil {
		t.Fatal("birth alone promoted readiness")
	}
	f.settleFull(t)
	if f.space.Committed {
		t.Fatal("test must exercise pre-publication space")
	}
	if err := f.create.journal.RequirePreparationWriterDomain(ctx, f.space); err != nil {
		t.Fatalf("future Committed/Work-zero/COMPLETE dependency: %v", err)
	}
	record, err := f.create.journal.Provision(ctx, f.outer)
	if err != nil {
		t.Fatal(err)
	}
	if record.CleanupState == "COMPLETE" {
		t.Fatal("test must precede storage-driven COMPLETE")
	}
	proof := f.settlement(t)
	if err = f.create.journal.CompleteProvisionCleanup(ctx, f.internal, proof); err != nil {
		t.Fatal(err)
	}
	if err = f.create.journal.CompleteProvisionCleanup(ctx, f.outer, proof); err != nil {
		t.Fatal(err)
	}
	if err = f.create.journal.RequirePreparationWriterDomain(ctx, f.space); err != nil {
		t.Fatalf("immutable COMPLETE history not consumable: %v", err)
	}
	if err = f.observe(t, f.outer, f.outerBirth); err == nil {
		t.Fatal("COMPLETE writer history amended")
	}
}

func TestPreparationWriterPassiveProofUsesReadonlyStore(t *testing.T) {
	f := newPreparationWriterFixture(t)
	f.settleFull(t)
	ctx := context.Background()
	guard, err := acquireManagementGuardAt(ctx, f.create.guard.root, f.create.guard.uid, ManagementShared)
	if err != nil {
		t.Fatal(err)
	}
	address := url.URL{Scheme: "file", Path: filepath.Join(f.create.directory, "supervisor.sqlite")}
	query := address.Query()
	query.Set("mode", "ro")
	address.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", address.String())
	if err != nil {
		guard.Close()
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	reader := &MetadataReader{store: &Store{db: db, dir: f.create.directory, productID: f.create.journal.productID, gate: guard}}
	defer reader.Close()
	if err = reader.RequirePreparationWriterDomain(ctx, f.space); err != nil {
		t.Fatalf("passive writer closure unavailable: %v", err)
	}
	if _, err = db.ExecContext(ctx, "CREATE TABLE passive_writer_must_be_readonly(value TEXT)"); err == nil {
		t.Fatal("passive proof used a writable connection")
	}
	if err = guard.Close(); err != nil {
		t.Fatal(err)
	}
	if err = reader.RequirePreparationWriterDomain(ctx, f.space); err == nil {
		t.Fatal("closed passive management guard admitted proof")
	}
}

func TestPreparationWriterRejectsLegacyObservedCompletion(t *testing.T) {
	f := newPreparationWriterFixture(t)
	ctx := context.Background()
	record, err := f.create.journal.Provision(ctx, f.internal)
	if err != nil {
		t.Fatal(err)
	}
	var desired, observed ProvisionProperties
	if err = json.Unmarshal(record.Desired, &desired); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(record.Observed.Attributes, &observed); err != nil {
		t.Fatal(err)
	}
	desired.Writer = nil
	observed.Writer = nil
	record.Desired = writerTestJSON(t, desired)
	record.Observed.Attributes = writerTestJSON(t, observed)
	if _, err = f.create.journal.db.ExecContext(ctx, "UPDATE provisioning_ledger SET record=? WHERE id=?", writerTestJSON(t, record), f.internal); err != nil {
		t.Fatal(err)
	}
	if _, err = f.create.journal.PreparationWriter(ctx, f.internal); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("legacy row acquired current proof: %v", err)
	}
	if err = f.create.journal.CompleteProvisionCleanup(ctx, f.internal, f.settlement(t)); err == nil {
		t.Fatal("legacy observed invocation promoted to proved COMPLETE")
	}
	if err = f.create.journal.ForbidPreparationWriterStart(ctx, f.internal, *f.writer.Birth); err == nil {
		t.Fatal("missing legacy birth became no-START authority")
	}
}

func TestPreparationWriterRequiresDurableBirthBeforeFullEvidence(t *testing.T) {
	f := newPreparationWriterFixture(t)
	ctx := context.Background()
	record, err := f.create.journal.Provision(ctx, f.internal)
	if err != nil {
		t.Fatal(err)
	}
	preBirth := f.internalBirth
	preBirth.Writer = &PreparationWriterRecord{Launch: f.writer.Launch}
	record.Observed.Attributes = writerTestJSON(t, preBirth)
	if _, err = f.create.journal.db.ExecContext(ctx, "UPDATE provisioning_ledger SET record=? WHERE id=?", writerTestJSON(t, record), f.internal); err != nil {
		t.Fatal(err)
	}
	full := f.internalBirth
	full.Writer = &f.writer
	if err = f.observe(t, f.internal, full); err == nil {
		t.Fatal("full evidence manufactured an unpersisted pre-ARM birth")
	}
	if err = f.observe(t, f.internal, f.internalBirth); err != nil {
		t.Fatal(err)
	}
	forbidden := *f.internalBirth.Writer
	forbidden.StartForbidden = true
	native := f.internalBirth
	native.Writer = &forbidden
	if err = f.observe(t, f.internal, native); err == nil {
		t.Fatal("ordinary observation bypassed exact-birth forbid CAS")
	}
}

func TestPreparationWriterHistoricalProofSurvivesInstalledBundleChange(t *testing.T) {
	f := newPreparationWriterFixture(t)
	f.settleFull(t)
	ctx := context.Background()
	manifest, err := f.create.journal.Installation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	manifest.BundleDigest = "sha256:" + strings.Repeat("9", 64)
	if _, err = f.create.journal.db.ExecContext(ctx, "UPDATE runtime_installations SET manifest=? WHERE id=?", writerTestJSON(t, manifest), f.create.journal.productID); err != nil {
		t.Fatal(err)
	}
	if err = f.create.journal.RequirePreparationWriterDomain(ctx, f.space); err != nil {
		t.Fatalf("historical original proof was reinterpreted against today's bundle: %v", err)
	}
	terminal := f.internalBirth
	terminal.Writer = nil
	terminal.Exit = &ProcessExit{Kind: "exit"}
	if err = f.observe(t, f.internal, terminal); err != nil {
		t.Fatalf("historical native terminal merge was mistaken for new dispatch: %v", err)
	}
	launch := f.writer.Launch
	launch.Generation = strings.Repeat("a", 32)
	launch.UnitName = "chatanium-image-preparer-" + launch.Generation + ".service"
	proposed := UnitIdentity{Name: launch.UnitName, Generation: launch.Generation, BootID: launch.BootID}
	properties := f.internalBirth
	properties.Name = launch.UnitName
	properties.Unit = &proposed
	properties.Writer = &PreparationWriterRecord{Launch: launch}
	properties.MountNamespace = nil
	properties.MountNamespaceDisposition = ""
	if err = f.create.journal.BeginProvision(ctx, ProvisionIntent{ID: "systemd-" + launch.Generation, Kind: "unit", Identity: launch.UnitName, ProductCreated: true, Desired: writerTestJSON(t, properties)}); err == nil {
		t.Fatal("unapproved old bundle acquired new dispatch authority")
	}
}

func TestPreparationWriterNewHelperCannotReplaceOriginalSourceProof(t *testing.T) {
	f := newPreparationWriterFixture(t)
	f.settleFull(t)
	ctx := context.Background()
	space := f.space
	space.ReusedSource = true
	space.Source = filepath.Join(filepath.Dir(space.Source), strings.Repeat("b", 32))
	tx, err := f.create.journal.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = f.create.journal.requireOriginalPreparationSource(ctx, tx, space); err == nil {
		t.Fatal("new current helper proof substituted for missing original acquisition")
	}
}

func TestPreparationWriterUnsupportedV1IsCleanupOnly(t *testing.T) {
	f := newPreparationWriterFixture(t)
	legacy := f.internalBirth
	writer := f.writer
	// Original v1 launch JSON had no filter_version member; preserve decoded 0.
	writer.Launch.FilterVersion = 0
	evidence := *writer.Evidence
	evidence.FilterVersion = 1
	evidence.FilterDigest = preparationUnsupportedFilterV1Digest
	writer.Evidence = &evidence
	legacy.Writer = &writer
	proof := f.settlement(t)
	legacy.Exit = &ProcessExit{Kind: "exit"}
	legacy.Absence = &proof
	legacy.CgroupEmpty = true
	if err := validateUnsupportedPreparationWriterV1(legacy); err != nil {
		t.Fatalf("exact unsupported immutable proof unavailable for quarantine: %v", err)
	}
	if err := validatePreparationSettlement(legacy); err == nil {
		t.Fatal("unsupported filter-v1 history became current writer-domain authority")
	}
	evidence.FilterDigest = "sha256:" + strings.Repeat("9", 64)
	if err := validateUnsupportedPreparationWriterV1(legacy); err == nil {
		t.Fatal("unsupported history accepted an arbitrary old filter digest")
	}
	evidence.FilterDigest = preparationUnsupportedFilterV1Digest
	writer.Evidence = nil
	writer.StartIntent = false
	if err := validateUnsupportedPreparationWriterV1(legacy); err == nil {
		t.Fatal("unsupported absence-only birth was promoted to full historical proof")
	}
}

func TestPreparationWriterMissingFilterIntentCannotForbid(t *testing.T) {
	f := newPreparationWriterFixture(t)
	ctx := context.Background()
	record, err := f.create.journal.Provision(ctx, f.internal)
	if err != nil {
		t.Fatal(err)
	}
	var desired, observed ProvisionProperties
	if err = json.Unmarshal(record.Desired, &desired); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(record.Observed.Attributes, &observed); err != nil {
		t.Fatal(err)
	}
	desired.Writer.Launch.FilterVersion = 0
	observed.Writer.Launch.FilterVersion = 0
	record.Desired = writerTestWithoutFilterIntent(t, desired)
	record.Observed.Attributes = writerTestWithoutFilterIntent(t, observed)
	if _, err = f.create.journal.db.ExecContext(ctx, "UPDATE provisioning_ledger SET record=? WHERE id=?", writerTestJSON(t, record), f.internal); err != nil {
		t.Fatal(err)
	}
	if err = f.create.journal.ForbidPreparationWriterStart(ctx, f.internal, *f.writer.Birth); err == nil {
		t.Fatal("old missing-filter pre-START birth acquired current no-START authority")
	}
	if _, err = f.create.journal.PreparationWriter(ctx, f.internal); err == nil {
		t.Fatal("old missing-filter partial history became current proof")
	}
}

func TestPreparationWriterCompleteV1RawHistoryIsNotCurrentAuthority(t *testing.T) {
	f := newPreparationWriterFixture(t)
	f.settleFull(t)
	ctx := context.Background()
	store := f.create.journal
	proof := f.settlement(t)
	saved := make(map[string]ProvisionRecord)
	rawSaved := make(map[string][]byte)
	for _, id := range []string{f.internal, f.outer} {
		if err := store.CompleteProvisionCleanup(ctx, id, proof); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{f.internal, f.outer} {
		record, err := store.Provision(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		var desired, observed ProvisionProperties
		if err = json.Unmarshal(record.Desired, &desired); err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(record.Observed.Attributes, &observed); err != nil {
			t.Fatal(err)
		}
		if desired.Writer != nil {
			desired.Writer.Launch.FilterVersion = 0
			record.Desired = writerTestWithoutFilterIntent(t, desired)
		}
		observed.Writer.Launch.FilterVersion = 0
		observed.Writer.Evidence.FilterVersion = 1
		observed.Writer.Evidence.FilterDigest = preparationUnsupportedFilterV1Digest
		record.Observed.Attributes = writerTestWithoutFilterIntent(t, observed)
		raw := writerTestJSON(t, record)
		if _, err = store.db.ExecContext(ctx, "UPDATE provisioning_ledger SET record=? WHERE id=?", raw, id); err != nil {
			t.Fatal(err)
		}
		saved[id], rawSaved[id] = record, raw
	}
	for _, id := range []string{f.internal, f.outer} {
		record, err := store.Provision(ctx, id)
		if err != nil {
			t.Fatalf("exact COMPLETE unsupported history unavailable for disposal: %s %v", id, err)
		}
		if !bytes.Equal(record.Desired, saved[id].Desired) || !bytes.Equal(record.Observed.Attributes, saved[id].Observed.Attributes) {
			t.Fatal("historical read backfilled the absent launch filter field")
		}
		var raw []byte
		if err = store.db.QueryRowContext(ctx, "SELECT record FROM provisioning_ledger WHERE id=?", id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw, rawSaved[id]) {
			t.Fatal("historical read rewrote immutable COMPLETE bytes")
		}
		if _, err = store.PreparationWriter(ctx, id); err == nil {
			t.Fatal("generic historical read granted current writer authority")
		}
		if err = store.ForbidPreparationWriterStart(ctx, id, *f.writer.Birth); err == nil {
			t.Fatal("unsupported COMPLETE history acquired current no-START authority")
		}
	}
	if err := store.RequirePreparationWriterDomain(ctx, f.space); err == nil {
		t.Fatal("unsupported raw history promoted current readiness")
	}
	pending := saved[f.internal]
	pending.CleanupState = "PENDING"
	if _, err := store.db.ExecContext(ctx, "UPDATE provisioning_ledger SET record=? WHERE id=?", writerTestJSON(t, pending), f.internal); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Provision(ctx, f.internal); err == nil {
		t.Fatal("unsupported pending history acquired COMPLETE-only read allowance")
	}
	if _, err := store.Provision(ctx, f.outer); err == nil {
		t.Fatal("outer historical read ignored pending internal companion")
	}
	corrupt := saved[f.internal]
	var observed ProvisionProperties
	if err := json.Unmarshal(corrupt.Observed.Attributes, &observed); err != nil {
		t.Fatal(err)
	}
	observed.Writer.Evidence.FilterDigest = "sha256:" + strings.Repeat("9", 64)
	corrupt.Observed.Attributes = writerTestWithoutFilterIntent(t, observed)
	if _, err := store.db.ExecContext(ctx, "UPDATE provisioning_ledger SET record=? WHERE id=?", writerTestJSON(t, corrupt), f.internal); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Provision(ctx, f.internal); err == nil {
		t.Fatal("arbitrary unsupported filter digest accepted as raw historical proof")
	}
}
