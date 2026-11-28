//go:build linux

package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sharedhost "github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"golang.org/x/sys/unix"
)

func terminalTestAnonymous(t *testing.T, g *ManagementGuard, payload []byte) *os.File {
	t.Helper()
	root, err := g.RootFD()
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Openat(root, ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "test-complete-anonymous-terminal-payload")
	if _, err = file.Write(payload); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = file.Sync(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	return file
}
func terminalTestProbe(t *testing.T, s *Store, g *ManagementGuard, approval []byte, txn string) TerminalCapability {
	t.Helper()
	ctx := context.Background()
	payloads := [2][]byte{[]byte(`{"probe":0}`), []byte(`{"probe":1}`)}
	files := [2]*os.File{terminalTestAnonymous(t, g, payloads[0]), terminalTestAnonymous(t, g, payloads[1])}
	defer files[0].Close()
	defer files[1].Close()
	record, err := s.BindTerminalPublicationProbe(ctx, g, approval, txn, files, payloads, 0)
	if err != nil {
		t.Fatal(err)
	}
	root, err := g.RootFD()
	if err != nil {
		t.Fatal(err)
	}
	for index, file := range files {
		if err = LinkAnonymous(file, root, filepath.Base(record.Paths[index])); err != nil {
			t.Fatal(err)
		}
	}
	if err = LinkAnonymous(files[0], root, filepath.Base(record.Paths[0])); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("no-replace publication did not reject collision: %v", err)
	}
	if err = unix.Renameat2(root, filepath.Base(record.Paths[0]), root, filepath.Base(record.Paths[1]), unix.RENAME_EXCHANGE); err != nil {
		t.Fatal(err)
	}
	if err = unix.Fsync(root); err != nil {
		t.Fatal(err)
	}
	evidence := TerminalProbeEvidence{CreatedAnonymous: true, LinkedNoReplace: true, NoReplaceRejected: true, Exchanged: true, Synced: true}
	record, err = s.RecordTerminalPublicationProbeExchange(ctx, g, record, evidence)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range record.Paths {
		if err = unix.Unlinkat(root, filepath.Base(path), 0); err != nil {
			t.Fatal(err)
		}
	}
	if err = unix.Fsync(root); err != nil {
		t.Fatal(err)
	}
	evidence.Absent = true
	capability, err := s.CompleteTerminalPublicationProbe(ctx, g, record, evidence)
	if err != nil {
		t.Fatal(err)
	}
	return capability
}
func TestTerminalPurgeSourceRetainsFenceAndWALAcrossClose(t *testing.T) {
	ctx := context.Background()
	f := newCreateStateFixture(t, sharedhost.EgressNone)
	if err := f.journal.cleanup(ctx, f.lease.Spec.InstanceID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.SetDesired(ctx, "STOPPED", strings.Repeat("e", 32)); err != nil {
		t.Fatal(err)
	}
	id, dir, oldGuard := f.journal.productID, f.directory, f.journal.gate
	if err := f.journal.installationLease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.Close(); err != nil {
		t.Fatal(err)
	}
	guard, err := acquireManagementGuardAt(ctx, oldGuard.root, oldGuard.uid, ManagementExclusive)
	if err != nil {
		t.Fatal(err)
	}
	store, err := openStoreDB(ctx, dir, false, guard)
	if err != nil {
		t.Fatal(err)
	}
	store.productID = id
	f.journal = store
	lease, err := store.AcquireLease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f.journal != nil {
			if f.journal.installationLease != nil {
				f.journal.installationLease.Close()
			}
			f.journal.Close()
		}
		guard.Close()
	})
	txn := strings.Repeat("f", 32)
	scope := []map[string]string{{"kind": "directory", "identity": dir, "action": "remove", "observation_digest": "owned-control"}}
	fields := map[string]any{"plan_id": txn, "installation_id": id, "expected_active_revision": "revision", "scope": scope}
	canonical, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	fields["plan_digest"] = provision.DomainDigest("chatanium-purge-plan-v1", canonical)
	approval, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	capability := terminalTestProbe(t, store, guard, approval, txn)
	t.Run("probe-only approval discovery is passive", func(t *testing.T) { terminalTestPassiveApproval(t, store, guard, approval, false) })
	var targets []TerminalObject
	for _, name := range []string{"runtime.sock", "management.sock", "installation.json.next", "supervisor.sqlite-wal", "supervisor.sqlite-shm", "supervisor.sqlite", "installation.json", "installation.lock"} {
		path := filepath.Join(dir, name)
		native, err := terminalObserve(path, name == "installation.json")
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, TerminalObject{Name: name, Native: native})
	}
	native, err := terminalObserve(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	targets = append(targets, TerminalObject{Name: filepath.Base(dir), Native: native})
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	proof := CleanupEvidence{BootID: strings.TrimSpace(string(boot)), JobsAbsent: true, ProcessesAbsent: true, TransportsClosed: true, MountsAbsent: true, OpenReferencesAbsent: true, QuotaReclaimed: true}
	fence, err := store.PrepareTerminalPurge(ctx, guard, capability, approval, txn, proof, targets, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !fence.Frozen {
		t.Fatal("terminal witness not durably frozen")
	}
	t.Run("renamed witness requires control fsync before frozen commit", func(t *testing.T) {
		interrupted := fence
		interrupted.Frozen = false
		if err := terminalWriteRecord(ctx, store, "terminal_fence", interrupted); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, "INSERT INTO metadata VALUES('mirror_pending','1') ON CONFLICT(key) DO UPDATE SET value=excluded.value"); err != nil {
			t.Fatal(err)
		}
		barrierFailure := errors.New("injected control directory fsync failure")
		called := false
		_, err := store.finishTerminalFreezeWithSync(ctx, guard, interrupted, func(directory *os.File) error {
			called = true
			actual, err := directory.Stat()
			if err != nil {
				t.Fatal(err)
			}
			expected, err := os.Stat(dir)
			if err != nil || !os.SameFile(actual, expected) {
				t.Fatalf("barrier did not cover exact Control directory: %v", err)
			}
			saved, err := store.TerminalPurgeFence(ctx)
			if err != nil || saved.Frozen {
				t.Fatalf("frozen committed before control sync: %+v %v", saved, err)
			}
			return barrierFailure
		})
		if !called || !errors.Is(err, barrierFailure) {
			t.Fatalf("visible renamed witness bypassed directory durability: called=%v err=%v", called, err)
		}
		saved, err := store.TerminalPurgeFence(ctx)
		if err != nil || saved.Frozen {
			t.Fatalf("failed directory sync committed frozen witness: %+v %v", saved, err)
		}
		var pending string
		if err := store.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='mirror_pending'").Scan(&pending); err != nil {
			t.Fatalf("failed directory sync cleared mirror intent: %v", err)
		}
		fence, err = store.finishTerminalFreeze(ctx, guard, saved)
		if err != nil || !fence.Frozen {
			t.Fatalf("durable rename recovery did not finish: %+v %v", fence, err)
		}
	})
	t.Run("fenced approval discovery is passive", func(t *testing.T) { terminalTestPassiveApproval(t, store, guard, approval, true) })
	if err = lease.BindOwner(ctx, testUnit("forbidden.service")); !errors.Is(err, ErrTerminalPurge) {
		t.Fatalf("already-open owner binding bypassed terminal fence: %v", err)
	}
	seal := TerminalPurgeSeal{Version: 1, InstallationID: id, Incarnation: fence.Incarnation, TransactionID: txn, ApprovalDigest: fence.ApprovalDigest, ApprovedPlan: approval, ReceiptPath: fence.ReceiptPath, SourceControl: fence.SourceControl, SourceDatabase: fence.SourceDatabase, FrozenManifest: fence.FrozenManifest, Remaining: fence.Remaining, AbsenceGuards: fence.AbsenceGuards}
	payload, err := json.Marshal(map[string]any{"seal": seal, "revision": 2})
	if err != nil {
		t.Fatal(err)
	}
	anonymous := terminalTestAnonymous(t, guard, payload)
	first, err := store.BindTerminalPurgePublication(ctx, guard, seal, anonymous, payload, 0)
	if err != nil {
		t.Fatal(err)
	}
	anonymous.Close()
	wal, err := terminalObserve(filepath.Join(dir, "supervisor.sqlite-wal"), false)
	if err != nil {
		t.Fatal(err)
	}
	shm, err := terminalObserve(filepath.Join(dir, "supervisor.sqlite-shm"), false)
	if err != nil {
		t.Fatal(err)
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenTerminalPurgeSource(ctx, dir, id, guard)
	if err != nil {
		t.Fatal(err)
	}
	f.journal = reopened
	lease, err = reopened.AcquireLease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	currentWAL, err := terminalObserve(wal.Path, false)
	if err != nil {
		t.Fatal(err)
	}
	currentSHM, err := terminalObserve(shm.Path, false)
	if err != nil {
		t.Fatal(err)
	}
	if !terminalIdentityMatches(wal, currentWAL, false) || !terminalIdentityMatches(shm, currentSHM, false) {
		t.Fatal("intent-only recovery changed frozen WAL/SHM native identities")
	}
	saved, err := reopened.TerminalPurgeFence(ctx)
	if err != nil || !terminalSameJSON(saved.Remaining, fence.Remaining) {
		t.Fatalf("finite terminal targets changed across close: %v", err)
	}
	fresh := terminalTestAnonymous(t, guard, payload)
	defer fresh.Close()
	if _, err = reopened.BindTerminalPurgePublication(ctx, guard, seal, fresh, payload, 0); err == nil {
		t.Fatal("stale anonymous publication attempt replaced source authority")
	}
	bound, err := reopened.BindTerminalPurgePublication(ctx, guard, seal, fresh, payload, first.Attempt)
	if err != nil || bound.Attempt != first.Attempt+1 {
		t.Fatalf("vanished prelink attempt did not resume through CAS: %+v %v", bound, err)
	}
	root, err := guard.RootFD()
	if err != nil {
		t.Fatal(err)
	}
	if err = LinkAnonymous(fresh, root, filepath.Base(seal.ReceiptPath)); err != nil {
		t.Fatal(err)
	}
	if err = unix.Fsync(root); err != nil {
		t.Fatal(err)
	}
	if err = VerifyTerminalPurgeSource(ctx, guard, seal); err != nil {
		t.Fatal(err)
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(seal.SourceDatabase.Path); err != nil {
		t.Fatal(err)
	}
	if err = VerifyTerminalPurgeSource(ctx, guard, seal); err != nil {
		t.Fatalf("source-DB removal stranded exact native witness: %v", err)
	}
	if _, err = OpenStore(ctx, dir, id, guard); !errors.Is(err, ErrTerminalPurge) {
		t.Fatalf("canonical-DB absence bypassed terminal receipt exclusion: %v", err)
	}
	foreign := []byte("unrelated recreated database")
	if err = os.WriteFile(seal.SourceDatabase.Path, foreign, 0600); err != nil {
		t.Fatal(err)
	}
	if err = VerifyTerminalPurgeSource(ctx, guard, seal); err == nil {
		t.Fatal("terminal source adopted recreated canonical database")
	}
	actual, err := os.ReadFile(seal.SourceDatabase.Path)
	if err != nil || string(actual) != string(foreign) {
		t.Fatalf("mismatched recreated source was changed: %q %v", actual, err)
	}
}

func TestLinkAnonymousPublishesHeldInodeWithoutReplacement(t *testing.T) {
	guard := testManagementGuard(t)
	root, err := guard.RootFD()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("complete source-owned anonymous body")
	file := terminalTestAnonymous(t, guard, payload)
	defer file.Close()
	var before, after unix.Stat_t
	if err = unix.Fstat(int(file.Fd()), &before); err != nil {
		t.Fatal(err)
	}
	if err = LinkAnonymous(file, root, "complete-publication"); err != nil {
		t.Fatal(err)
	}
	if err = unix.Fstatat(root, "complete-publication", &after, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Uid != after.Uid || before.Gid != after.Gid || before.Mode != after.Mode || after.Nlink != 1 {
		t.Fatal("anonymous publication did not preserve the exact held inode and protection")
	}
	if err = LinkAnonymous(file, root, "complete-publication"); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("anonymous publication replaced an existing name: %v", err)
	}
	actual, err := os.ReadFile(filepath.Join(guard.root, "complete-publication"))
	if err != nil || string(actual) != string(payload) {
		t.Fatalf("existing complete publication changed: %q %v", actual, err)
	}
	named, err := os.OpenFile(filepath.Join(guard.root, "already-named"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer named.Close()
	if err = LinkAnonymous(named, root, "invalid-named-source"); err == nil {
		t.Fatal("named regular file accepted as anonymous source")
	}
	if err = LinkAnonymous(file, root, "../escape"); err == nil {
		t.Fatal("anonymous publication accepted a path instead of one destination name")
	}
}

func terminalTestPassiveApproval(t *testing.T, store *Store, guard *ManagementGuard, approval []byte, fenced bool) {
	t.Helper()
	ctx := context.Background()
	before := make([]TerminalNativeIdentity, 0, 3)
	for _, name := range []string{"supervisor.sqlite", "supervisor.sqlite-wal", "supervisor.sqlite-shm"} {
		observed, err := terminalObserve(filepath.Join(store.dir, name), name != "supervisor.sqlite-shm")
		if err != nil {
			t.Fatal(err)
		}
		before = append(before, observed)
	}
	reader, err := OpenTerminalPurgeMetadata(ctx, store.dir, store.productID, guard)
	if err != nil {
		t.Fatal(err)
	}
	if fenced {
		fence, err := reader.TerminalPurgeFence(ctx)
		if err != nil || string(fence.ApprovedPlan) != string(approval) {
			reader.Close()
			t.Fatalf("passive frozen original approval unavailable: %v", err)
		}
	} else {
		probe, err := reader.ActiveTerminalPublicationProbe(ctx)
		if err != nil || string(probe.ApprovedPlan) != string(approval) {
			reader.Close()
			t.Fatalf("passive probe original approval unavailable: %v", err)
		}
	}
	if _, err := reader.store.db.ExecContext(ctx, "CREATE TABLE terminal_discovery_must_be_readonly(value TEXT)"); err == nil || !strings.Contains(strings.ToLower(err.Error()), "readonly") {
		reader.Close()
		t.Fatalf("passive terminal discovery opened writable SQL: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	for _, expected := range before {
		actual, err := terminalObserve(expected.Path, expected.Digest != "")
		if err != nil || !terminalIdentityMatches(expected, actual, false) {
			t.Fatalf("passive approval reader changed source native identity: %s %v", expected.Path, err)
		}
	}
}

func TestTerminalAccountGuardOriginalGroupAndUnderscore(t *testing.T) {
	properties := ProvisionProperties{Name: "_chatanium-worker", GID: 27183, Source: "group"}
	guard := TerminalGuard{Kind: "account", Name: properties.Name, GID: properties.GID, GroupOnly: true}
	if err := validateTerminalAccountGuardSource(guard, properties); err != nil {
		t.Fatalf("original underscore group guard rejected: %v", err)
	}
	wrongDisposition := guard
	wrongDisposition.GroupOnly = false
	if err := validateTerminalAccountGuardSource(wrongDisposition, properties); err == nil {
		t.Fatal("group-only source was reinterpreted as root user")
	}
	reusedID := guard
	reusedID.GID++
	if err := validateTerminalAccountGuardSource(reusedID, properties); err == nil {
		t.Fatal("reused numeric group identity accepted")
	}
	reusedName := guard
	reusedName.Name = "_replacement"
	if err := validateTerminalAccountGuardSource(reusedName, properties); err == nil {
		t.Fatal("changed original account name accepted")
	}
	user := ProvisionProperties{Name: "_chatanium-worker", UID: 27183, GID: 27183}
	userGuard := TerminalGuard{Kind: "account", Name: user.Name, UID: user.UID, GID: user.GID}
	if err := validateTerminalAccountGuardSource(userGuard, user); err != nil {
		t.Fatalf("underscore user name rejected: %v", err)
	}
	userGuard.UID = 0
	user.UID = 0
	if err := validateTerminalAccountGuardSource(userGuard, user); err == nil {
		t.Fatal("numeric root-user guard accepted")
	}
}
