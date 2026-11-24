package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func digest(letter string) string { return "sha256:" + strings.Repeat(letter, 64) }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func expect(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

const testMetadata = 4 << 20
const testLog = 1 << 20
const testCache = 2 << 20

func fixture(t *testing.T, budget int64) (context.Context, string, Installation, *Store, Configuration) {
	t.Helper()
	ctx, dir := t.Context(), filepath.Join(t.TempDir(), "installation")
	must(t, os.Mkdir(dir, 0o700))
	spec := Installation{InstallationIdentity: InstallationIdentity{ID: "test-install", Owner: "uid:1", Target: "linux/amd64/systrap",
		BundleDigest: digest("a"), EngineDigest: digest("b")}, PlanDigest: digest("c"), BudgetBytes: budget,
		MetadataBytes: testMetadata, LogBytes: testLog}
	s, err := Create(ctx, dir, spec)
	must(t, err)
	offline, err := s.BeginOfflineEpoch(ctx, EpochIdentity{BootID: "boot1", PID: 1, StartIdentity: "offline1"})
	must(t, err)
	i, err := s.ReserveImage(ctx, offline.ID, "", digest("d"), testCache)
	must(t, err)
	proof := PublishProof{WritersExited: true, Verified: true, ReadOnly: true, Synchronized: true}
	must(t, s.StageImage(ctx, offline.ID, i.ID, proof))
	approval := Approval{ModuleID: "first", ReviewDigest: digest("e"), ImageDigest: i.Digest, ImageGeneration: i.ID, DeclarationDigest: digest("f"),
		ResourceFormat: VolumeResourceFormat, UID: 1000, GID: 1000, PersistentBytes: MinVolumeBytes, ScratchBytes: MinVolumeBytes,
		CPUMillicores: 100, MemoryBytes: 6 << 20, MaxPIDs: 16, Network: NetworkProfile{Mode: NetworkNone}}
	second := approval
	second.ModuleID, second.ReviewDigest = "second", digest("1")
	config := Configuration{Revision: digest("2"), ConfigDigest: digest("3"), Approvals: []Approval{approval, second}}
	expect(t, s.Configure(ctx, offline.ID, "", config), ErrApprovalMismatch)
	must(t, s.PublishImage(ctx, offline.ID, i.ID, proof))
	must(t, s.Configure(ctx, offline.ID, "", config))
	must(t, s.Activate(ctx, offline.ID, spec.PlanDigest, config.Revision))
	must(t, s.EndEpoch(ctx, offline.ID))
	return ctx, dir, spec, s, config
}

func req(epoch Epoch, config Configuration, module int, id string) RunRequest {
	return RunRequest{EpochID: epoch.ID, InstanceID: strings.Repeat(id, 32), ModuleID: config.Approvals[module].ModuleID,
		ConfigRevision: config.Revision, ReviewDigest: config.Approvals[module].ReviewDigest}
}

func TestConcurrentBudgetAndStopFence(t *testing.T) {
	// The budget admits one run exactly, even under simultaneous admission
	// requests on independently opened SQLite connections.
	ctx, dir, spec, s, config := fixture(t, testMetadata+testCache+2*MinVolumeBytes+testLog)
	defer s.Close()
	other, err := Open(ctx, dir, spec.InstallationIdentity)
	must(t, err)
	defer other.Close()
	epoch, err := s.BeginEpoch(ctx, EpochIdentity{BootID: "boot1", PID: 1, StartIdentity: "start1"})
	must(t, err)
	type result struct {
		run Run
		err error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for j, a := range []*Store{s, other} {
		go func() {
			<-start
			run, err := a.AdmitRun(ctx, req(epoch, config, j, []string{"4", "5"}[j]))
			results <- result{run, err}
		}()
	}
	close(start)
	var admitted Run
	for range 2 {
		r := <-results
		if r.err == nil {
			if admitted.Key.ID != "" {
				t.Fatal("two runs admitted into a single-run budget")
			}
			admitted = r.run
		} else {
			expect(t, r.err, ErrBudgetExceeded)
		}
	}
	if admitted.Key.ID == "" {
		t.Fatal("neither run admitted")
	}
	usage, err := s.Usage(ctx)
	must(t, err)
	if usage.Total() != spec.BudgetBytes {
		t.Fatalf("simultaneous charge = %+v, want exact fit", usage)
	}
	must(t, other.RequestStop(ctx, epoch.ID))
	expect(t, s.BeginLaunch(ctx, admitted.Key, PersistentObservation{}), ErrCleanupPending)
	_, err = s.AdmitRun(ctx, req(epoch, config, 0, "6"))
	expect(t, err, ErrState)
	must(t, s.CancelRun(ctx, epoch.ID, admitted.Key))
	usage, err = s.Usage(ctx)
	must(t, err)
	if usage.ScratchBytes != 0 || usage.LogBytes != 0 || usage.PersistentBytes != MinVolumeBytes {
		t.Fatalf("unexpected cancelled run charge: %+v", usage)
	}
}

func TestCrashKeepsWriterUntilCleanupProof(t *testing.T) {
	ctx, dir, spec, s, config := fixture(t, 128<<20)
	epoch, err := s.BeginEpoch(ctx, EpochIdentity{BootID: "boot1", PID: 1, StartIdentity: "start1"})
	must(t, err)
	run, err := s.AdmitRun(ctx, req(epoch, config, 0, "4"))
	must(t, err)
	must(t, s.BeginLaunch(ctx, run.Key, PersistentObservation{}))
	backing := PersistentObservation{Exists: true, SizeBytes: MinVolumeBytes, NativeID: "native-file:1"}
	expect(t, s.RecordPersistent(ctx, run.Key, backing), ErrIdentity)
	must(t, s.RecordPersistentCreation(ctx, run.Key, PersistentObservation{Exists: true, NativeID: backing.NativeID}))
	must(t, s.RecordPersistent(ctx, run.Key, backing))
	must(t, s.RecordEngine(ctx, run.Key, "native-engine:1"))
	must(t, s.MarkRunning(ctx, run.Key))
	must(t, s.StartWorker(ctx, epoch.ID))
	expect(t, s.EndEpoch(ctx, epoch.ID), ErrCleanupPending)
	must(t, s.Close()) // no graceful StopRun/EndEpoch

	s, err = Open(ctx, dir, spec.InstallationIdentity)
	must(t, err)
	defer s.Close()
	next, err := s.BeginEpoch(ctx, EpochIdentity{BootID: "boot2", PID: 1, StartIdentity: "start2"})
	must(t, err)
	records, err := s.Runs(ctx)
	must(t, err)
	if len(records) != 1 || !records[0].CleanupPending || records[0].State != Unknown || records[0].Desired != DesiredStopped || records[0].EgressState != EgressSealed || !records[0].LaunchBegun {
		t.Fatalf("prior run not fenced: %+v", records)
	}
	expect(t, s.StartWorker(ctx, next.ID), ErrCleanupPending)
	must(t, s.RecoverWorker(ctx, next.ID, epoch.ID, RemovalProof{WritersExited: true, FilesAbsent: true}))
	expect(t, s.CancelRun(ctx, next.ID, run.Key), ErrCleanupPending)
	expect(t, s.ReleaseRun(ctx, next.ID, run.Key, RunCleanup{ChildrenExited: true, BackingClosed: true}), ErrCleanupPending)
	_, err = s.AdmitRun(ctx, req(next, config, 0, "5"))
	expect(t, err, ErrVolumeBusy)
	expect(t, s.ReleaseRun(ctx, next.ID, run.Key, RunCleanup{
		ChildrenExited: true, BackingClosed: true, TemporaryFilesAbsent: true, PersistentBackingAbsent: true,
	}), ErrIdentity)
	must(t, s.ReleaseRun(ctx, next.ID, run.Key, RunCleanup{ChildrenExited: true, BackingClosed: true, TemporaryFilesAbsent: true}))
	fresh, err := s.AdmitRun(ctx, req(next, config, 0, "5"))
	must(t, err)
	if fresh.Persistent.ID != run.Persistent.ID || fresh.Persistent.NativeID != backing.NativeID || fresh.ScratchID == run.ScratchID {
		t.Fatalf("incorrect volume reuse or scratch identity: %+v", fresh)
	}
	expect(t, s.BeginLaunch(ctx, fresh.Key, PersistentObservation{}), ErrIdentity)
	must(t, s.BeginLaunch(ctx, fresh.Key, backing))
}

func TestInterruptedVolumeBirthReleasesOnlyAfterAbsence(t *testing.T) {
	ctx, dir, spec, s, config := fixture(t, 128<<20)
	epoch, err := s.BeginEpoch(ctx, EpochIdentity{BootID: "boot1", PID: 1, StartIdentity: "start1"})
	must(t, err)
	run, err := s.AdmitRun(ctx, req(epoch, config, 0, "4"))
	must(t, err)
	birth := PersistentObservation{Exists: true, NativeID: "native-file:1"}
	expect(t, s.BeginLaunch(ctx, run.Key, PersistentObservation{Exists: true, NativeID: birth.NativeID, SizeBytes: MinVolumeBytes}), ErrIdentity)
	must(t, s.BeginLaunch(ctx, run.Key, PersistentObservation{}))
	must(t, s.RecordPersistentCreation(ctx, run.Key, birth))
	expect(t, s.RecordPersistent(ctx, run.Key, PersistentObservation{Exists: true, NativeID: "wrong-id", SizeBytes: MinVolumeBytes}), ErrIdentity)
	must(t, s.Close()) // the file may have been published, but never reached ROOTS_READY

	s, err = Open(ctx, dir, spec.InstallationIdentity)
	must(t, err)
	defer s.Close()
	next, err := s.BeginEpoch(ctx, EpochIdentity{BootID: "boot2", PID: 1, StartIdentity: "start2"})
	must(t, err)
	pending, err := s.Run(ctx, run.Key)
	must(t, err)
	if !pending.CleanupPending || pending.Persistent.Initialized ||
		pending.Persistent.NativeID != birth.NativeID || pending.Persistent.CreationRunID != run.Key.ID {
		t.Fatalf("provisional backing did not survive fencing: %+v", pending)
	}
	proof := RunCleanup{ChildrenExited: true, BackingClosed: true, TemporaryFilesAbsent: true}
	expect(t, s.ReleaseRun(ctx, next.ID, run.Key, proof), ErrCleanupPending)
	proof.PersistentBackingAbsent = true
	must(t, s.ReleaseRun(ctx, next.ID, run.Key, proof))
	fresh, err := s.AdmitRun(ctx, req(next, config, 0, "5"))
	must(t, err)
	if fresh.Persistent.ID != run.Persistent.ID || fresh.Persistent.NativeID != "" ||
		fresh.Persistent.CreationRunID != "" || fresh.Persistent.Initialized {
		t.Fatalf("incorrect birth rollback: %+v", fresh.Persistent)
	}
	must(t, s.BeginLaunch(ctx, fresh.Key, PersistentObservation{}))
}

func TestBackupFenceAndFrozenPurge(t *testing.T) {
	ctx, dir, spec, s, config := fixture(t, 128<<20)
	defer s.Close()
	epoch, err := s.BeginOfflineEpoch(ctx, EpochIdentity{BootID: "boot1", PID: 1, StartIdentity: "update1"})
	must(t, err)
	backup, err := s.BeginBackup(ctx, epoch.ID, 8<<20, true)
	must(t, err)
	if backup.SQLiteBytes <= 0 || backup.SQLiteBytes > backup.MaxBytes || len(backup.Images) != 1 || !backup.UpdatePending {
		t.Fatalf("invalid backup snapshot: %+v", backup)
	}
	_, err = s.ReservePreparation(ctx, epoch.ID, 1<<20)
	expect(t, err, ErrCleanupPending)
	bdir := filepath.Join(dir, filepath.FromSlash(backup.Path))
	must(t, os.MkdirAll(bdir, 0o700))
	expect(t, s.SnapshotDatabase(ctx, "wrong-epoch", backup.ID), ErrIdentity)
	must(t, s.SnapshotDatabase(ctx, epoch.ID, backup.ID))
	expect(t, s.SnapshotDatabase(ctx, epoch.ID, backup.ID), os.ErrExist)
	snapshot, err := Open(ctx, bdir, spec.InstallationIdentity)
	must(t, err)
	frozen, err := snapshot.Configuration(ctx)
	closeErr := snapshot.Close()
	must(t, errors.Join(err, closeErr))
	if frozen.Revision != config.Revision || frozen.ConfigDigest != config.ConfigDigest || len(frozen.Approvals) != len(config.Approvals) {
		t.Fatalf("backup contains a mismatched configuration revision: %+v", frozen)
	}
	must(t, s.CompleteBackup(ctx, epoch.ID, backup.ID, BackupProof{WritersExited: true, Verified: true, Synchronized: true}))
	must(t, s.FinishUpdate(ctx, epoch.ID, backup.ID, spec.InstallationIdentity, digest("7")))
	empty := Configuration{Revision: digest("8"), ConfigDigest: digest("9")}
	must(t, s.Configure(ctx, epoch.ID, config.Revision, empty))
	expect(t, s.MarkImagePending(ctx, epoch.ID, backup.Images[0].ID), ErrReferenced)
	must(t, s.BeginUninstall(ctx, epoch.ID))
	removed := RemovalProof{WritersExited: true, FilesAbsent: true}
	must(t, s.CompleteUninstall(ctx, epoch.ID, removed))
	plan, err := s.PlanPurge(ctx)
	must(t, err)
	_, err = s.BeginPurge(ctx, epoch.ID, digest("a"))
	expect(t, err, ErrApprovalMismatch)
	_, err = s.BeginPurge(ctx, epoch.ID, plan.Digest)
	must(t, err)
	must(t, s.EndEpoch(ctx, epoch.ID))
	epoch, err = s.BeginOfflineEpoch(ctx, EpochIdentity{BootID: "boot1", PID: 1, StartIdentity: "purge1"})
	must(t, err)
	again, err := s.BeginPurge(ctx, epoch.ID, plan.Digest)
	must(t, err)
	if again.Digest != plan.Digest || len(again.Images) != 1 || len(again.Backups) != 1 {
		t.Fatalf("frozen purge scope changed: %+v", again)
	}
	expect(t, s.CompletePurge(ctx, epoch.ID, plan.Digest, RemovalProof{WritersExited: true}), ErrCleanupPending)
	must(t, s.CompletePurge(ctx, epoch.ID, plan.Digest, removed))
	install, err := s.Installation(ctx)
	must(t, err)
	if install.State != Purged || install.PurgeDigest != plan.Digest {
		t.Fatalf("terminal marker did not retain approval: %+v", install)
	}
}

func TestSealedBackupRebindsOnlyRestoredVolume(t *testing.T) {
	ctx, dir, spec, live, config := fixture(t, 128<<20)
	defer live.Close()
	identity := EpochIdentity{BootID: "boot1", PID: 1, StartIdentity: "source"}
	epoch, err := live.BeginEpoch(ctx, identity)
	must(t, err)
	run, err := live.AdmitRun(ctx, req(epoch, config, 0, "4"))
	must(t, err)
	must(t, live.BeginLaunch(ctx, run.Key, PersistentObservation{}))
	present := PersistentObservation{Exists: true, NativeID: "source-inode"}
	must(t, live.RecordPersistentCreation(ctx, run.Key, present))
	present.SizeBytes = MinVolumeBytes
	must(t, live.RecordPersistent(ctx, run.Key, present))
	must(t, live.StopRun(ctx, run.Key))
	must(t, live.ReleaseRun(ctx, epoch.ID, run.Key, RunCleanup{
		ChildrenExited: true, BackingClosed: true, TemporaryFilesAbsent: true,
	}))
	must(t, live.EndEpoch(ctx, epoch.ID))

	epoch, err = live.BeginOfflineEpoch(ctx, identity)
	must(t, err)
	backup, err := live.BeginBackup(ctx, epoch.ID, 32<<20, true)
	must(t, err)
	bdir := filepath.Join(dir, filepath.FromSlash(backup.Path))
	must(t, os.MkdirAll(bdir, 0o700))
	must(t, live.SnapshotDatabase(ctx, epoch.ID, backup.ID))
	binding := BackupVolumeBinding{VolumeID: run.Persistent.ID, SourceNativeID: present.NativeID,
		NativeID: "archive-inode", Digest: digest("7"), SizeBytes: present.SizeBytes}
	must(t, live.SealBackupSnapshot(ctx, epoch.ID, backup.ID, []BackupVolumeBinding{binding}))
	manifestDigest := digest("8")
	srcVol, err := live.Volumes(ctx)
	must(t, err)
	if len(srcVol) != 1 || srcVol[0].NativeID != present.NativeID {
		t.Fatalf("source identities changed: %+v", srcVol)
	}
	_, err = live.RestoreBinding(ctx, backup.ID, manifestDigest)
	expect(t, err, ErrApprovalMismatch)

	archive, err := Open(ctx, bdir, spec.InstallationIdentity)
	must(t, err)
	copiedVol, err := archive.Volumes(ctx)
	must(t, err)
	if len(copiedVol) != 1 || copiedVol[0].NativeID != binding.NativeID {
		t.Fatalf("archive does not bind its copied volume: %+v", copiedVol)
	}
	retained, err := archive.Backups(ctx)
	must(t, err)
	if len(retained) != 0 {
		t.Fatalf("restored ledger contains uncopied source history: %+v", retained)
	}
	_, err = archive.BeginOfflineEpoch(ctx, identity)
	expect(t, err, ErrCleanupPending)
	must(t, archive.Close())

	raw, err := os.ReadFile(filepath.Join(bdir, DatabaseName))
	must(t, err)
	stagedDir := filepath.Join(t.TempDir(), "restore")
	must(t, os.Mkdir(stagedDir, 0o700))
	must(t, os.WriteFile(filepath.Join(stagedDir, DatabaseName), raw, 0o600))
	stage, err := Open(ctx, stagedDir, spec.InstallationIdentity)
	must(t, err)
	defer stage.Close()
	binding.SourceNativeID, binding.NativeID = binding.NativeID, "restored-inode"
	bad := binding
	bad.Digest = digest("9")
	expect(t, stage.RebindRestoredVolumes(ctx, backup.ID, manifestDigest, []BackupVolumeBinding{bad}), ErrApprovalMismatch)
	must(t, stage.RebindRestoredVolumes(ctx, backup.ID, manifestDigest, []BackupVolumeBinding{binding}))
	_, err = stage.RestoreBinding(ctx, backup.ID, digest("9"))
	expect(t, err, ErrApprovalMismatch)
	completed, err := stage.RestoreBinding(ctx, backup.ID, manifestDigest)
	must(t, err)
	if !completed {
		t.Fatal("verified restore did not survive a repeated lookup")
	}

	epoch, err = stage.BeginEpoch(ctx, identity)
	must(t, err)
	fresh, err := stage.AdmitRun(ctx, req(epoch, config, 0, "5"))
	must(t, err)
	expect(t, stage.BeginLaunch(ctx, fresh.Key, present), ErrIdentity)
	present.NativeID = binding.NativeID
	must(t, stage.BeginLaunch(ctx, fresh.Key, present))
	_, err = stage.RestoreBinding(ctx, backup.ID, manifestDigest)
	expect(t, err, ErrState)
	persisted, err := stage.RestoredReceiptDigest(ctx)
	must(t, err)
	if persisted != manifestDigest {
		t.Fatalf("restore receipt digest = %q, want %q", persisted, manifestDigest)
	}
}
