//go:build linux

package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/thirdscam/chatanium/internal/legacy/host"
	"golang.org/x/sys/unix"
)

type terminalResumeFixture struct {
	native   *terminalNativeContext
	approval PurgeApproval
	receipt  terminalReceipt
	database int
	witness  int
	lock     int
	helper   string
}

// This fixture starts at the closed, source-frozen receipt boundary. It does not
// stand in for Store fencing: the tests exercise the real post-SQLite authority,
// anonymous publication, exchange, native deletion, discovery and retirement.
func newTerminalResumeFixture(t *testing.T, databaseComplete bool) *terminalResumeFixture {
	t.Helper()
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "management")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	native, err := acquireTerminalNativeAt(ctx, root, RuntimeInstallationID("terminal-resume"))
	if err != nil {
		t.Fatal(err)
	}
	fixture := &terminalResumeFixture{native: native, helper: filepath.Join(root, "retired-helper")}
	t.Cleanup(func() {
		if err := fixture.native.Close(); err != nil {
			t.Error(err)
		}
	})
	if err = os.MkdirAll(native.controlPath, 0700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(native.controlPath, "supervisor.sqlite")
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	_, createErr := db.Exec("CREATE TABLE terminal_fixture (value TEXT NOT NULL); INSERT INTO terminal_fixture VALUES ('closed source')")
	closeErr := db.Close()
	if createErr != nil || closeErr != nil {
		t.Fatalf("creating and closing actual SQLite source: %v, %v", createErr, closeErr)
	}
	if err = os.Chmod(databasePath, 0600); err != nil {
		t.Fatal(err)
	}
	witnessPath := filepath.Join(native.controlPath, "installation.json")
	if err = os.WriteFile(witnessPath, []byte("source-frozen incarnation/transaction witness\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(native.controlPath, "installation.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(terminalControlNames)+3)
	for _, name := range terminalControlNames {
		paths = append(paths, filepath.Join(native.controlPath, name))
	}
	paths = append(paths, native.controlPath, filepath.Dir(native.controlPath), filepath.Dir(filepath.Dir(native.controlPath)))
	var targets []host.TerminalObject
	for index, path := range paths {
		observed, err := terminalObserve(path)
		if err != nil {
			t.Fatal(err)
		}
		if path == witnessPath {
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			observed.Digest, err = streamDigest(file)
			file.Close()
			if err != nil {
				t.Fatal(err)
			}
			fixture.witness = index
		}
		if path == databasePath {
			fixture.database = index
		}
		if filepath.Base(path) == "installation.lock" {
			fixture.lock = index
		}
		targets = append(targets, host.TerminalObject{Name: filepath.Base(path), Native: host.TerminalNativeIdentity(observed)})
	}
	approval := PurgeApproval{
		InstallationID: native.installationID, PlanID: "original-terminal-plan", ExpectedActiveRevision: "original-active-revision",
		ManagementAnchor:    host.ManagementAnchorObservation{Root: host.TerminalNativeIdentity(native.rootIdentity), Lock: host.TerminalNativeIdentity(native.lockIdentity), Marker: host.ManagementMarker},
		TerminalReceiptPath: native.receiptPath,
	}
	approval.PublicationProbePaths = [2]string{filepath.Join(root, terminalStageName(approval.InstallationID, approval.PlanID, 0)), filepath.Join(root, terminalStageName(approval.InstallationID, approval.PlanID, 1))}
	for _, target := range targets {
		if target.Native.Absent {
			continue
		}
		observation, err := digest("terminal-native-resume-observation-v1", target.Native)
		if err != nil {
			t.Fatal(err)
		}
		approval.Scope = append(approval.Scope, ApprovedObject{Kind: target.Native.Kind, Identity: target.Native.Path, Action: "remove", ObservationDigest: observation})
	}
	approval.Scope = append(approval.Scope, ApprovedObject{Kind: "file", Identity: fixture.helper, Action: "remove", ObservationDigest: "original-retired-helper-observation"})
	approval.PlanDigest, err = PurgePlanDigest(approval)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := json.Marshal(approval)
	if err != nil {
		t.Fatal(err)
	}
	fence := host.TerminalFence{
		Version: 1, InstallationID: string(approval.InstallationID), Incarnation: "original-incarnation", TransactionID: approval.PlanID,
		ApprovalDigest: approval.PlanDigest, ApprovedPlan: approved, ReceiptPath: native.receiptPath, Frozen: true,
		SourceControl: targets[len(terminalControlNames)].Native, SourceDatabase: targets[fixture.database].Native, FrozenManifest: targets[fixture.witness].Native,
		Remaining: targets, AbsenceGuards: []host.TerminalGuard{{Kind: "path", Path: fixture.helper}},
	}
	fixture.approval = approval
	fixture.receipt, err = native.receiptFromFence(fence, approval)
	if err != nil {
		t.Fatal(err)
	}
	fixture.receipt = publishTerminalResumeReceipt(t, native, fixture.receipt, filepath.Base(native.receiptPath))
	fixture.completeThrough(t, fixture.database-1)
	fixture.advance(t, fixture.database, terminalRemoving)
	if err = terminalDeleteTarget(fixture.receipt.Targets[fixture.database]); err != nil {
		t.Fatal(err)
	}
	if databaseComplete {
		fixture.advance(t, fixture.database, terminalComplete)
	}
	return fixture
}

func publishTerminalResumeReceipt(t *testing.T, native *terminalNativeContext, receipt terminalReceipt, name string) terminalReceipt {
	t.Helper()
	file, identity, err := terminalAnonymous(native.root)
	if err != nil {
		t.Fatalf("mandatory native anonymous publication: %v", err)
	}
	defer file.Close()
	identity.Path = native.receiptPath
	receipt.Publication = identity
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err = terminalWriteAnonymous(file, raw); err != nil {
		t.Fatal(err)
	}
	if err = terminalLink(native.root, file, name); err != nil {
		t.Fatalf("mandatory native no-replace anonymous link: %v", err)
	}
	if err = native.root.Sync(); err != nil {
		t.Fatal(err)
	}
	observed, _, err := native.read(name)
	if err != nil {
		t.Fatal(err)
	}
	return observed
}

func (fixture *terminalResumeFixture) advance(t *testing.T, index int, state uint8) {
	t.Helper()
	next := fixture.receipt
	next.Targets = append([]terminalTarget(nil), fixture.receipt.Targets...)
	next.Targets[index].State = state
	next.Revision++
	var err error
	fixture.receipt, err = fixture.native.persistProgress(fixture.receipt, next)
	if err != nil {
		t.Fatal(err)
	}
}

func (fixture *terminalResumeFixture) completeThrough(t *testing.T, last int) {
	t.Helper()
	for index := 0; index <= last; index++ {
		if fixture.receipt.Targets[index].State == terminalComplete {
			continue
		}
		if fixture.receipt.Targets[index].State == terminalPending {
			fixture.advance(t, index, terminalRemoving)
		}
		if err := terminalDeleteTarget(fixture.receipt.Targets[index]); err != nil {
			t.Fatal(err)
		}
		fixture.advance(t, index, terminalComplete)
	}
}

func (fixture *terminalResumeFixture) reopen(t *testing.T) {
	t.Helper()
	root, id := fixture.native.rootPath, fixture.native.installationID
	if err := fixture.native.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	fixture.native, err = acquireTerminalNativeAt(context.Background(), root, id)
	if err != nil {
		t.Fatal(err)
	}
}

func (fixture *terminalResumeFixture) originalPlan(t *testing.T) {
	t.Helper()
	plan, found, err := fixture.native.approvedPlan(context.Background())
	if err != nil || !found || !reflect.DeepEqual(plan, fixture.approval) {
		t.Fatalf("receipt discovery changed original full approval: found=%v plan=%+v err=%v", found, plan, err)
	}
}

func (fixture *terminalResumeFixture) finish(t *testing.T) {
	t.Helper()
	result, found, err := fixture.native.resumeSource(context.Background(), fixture.approval)
	if err != nil || !found || result.InstallationID != fixture.approval.InstallationID || len(result.Removed) != len(fixture.receipt.Targets) || len(result.Pending) != 0 || len(result.Failures) != 0 {
		t.Fatalf("terminal dispatch did not finish exact original scope: found=%v result=%+v err=%v", found, result, err)
	}
	for _, target := range fixture.receipt.Targets {
		requireTerminalResumeAbsent(t, target.Native.Path)
	}
	requireTerminalResumeAbsent(t, fixture.native.receiptPath)
	requireTerminalResumeAbsent(t, fixture.helper)
	entries, err := os.ReadDir(fixture.native.rootPath)
	if err != nil || len(entries) != 1 || entries[0].Name() != ".management.lock" {
		t.Fatalf("terminal authority/helper/stage residue: entries=%v err=%v", entries, err)
	}
	if err = fixture.native.validate(); err != nil {
		t.Fatalf("retained shared native anchor changed: %v", err)
	}
	if plan, found, err := fixture.native.approvedPlan(context.Background()); err != nil || found || plan.PlanDigest != "" {
		t.Fatalf("retired authority was rediscovered: found=%v plan=%+v err=%v", found, plan, err)
	}
	if result, found, err := fixture.native.resumeSource(context.Background(), fixture.approval); err != nil || found || len(result.Removed) != 0 {
		t.Fatalf("missing receipt invented successful deletion authority: found=%v result=%+v err=%v", found, result, err)
	}
}

func requireTerminalResumeAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("expected physical absence of %s: %v", path, err)
	}
}

func TestTerminalResumeOriginalApprovalAfterDatabaseUnlink(t *testing.T) {
	for _, complete := range []bool{false, true} {
		name := "unlink-before-complete"
		if complete {
			name = "database-complete-with-survivors"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newTerminalResumeFixture(t, complete)
			requireTerminalResumeAbsent(t, fixture.receipt.Source.Database.Path)
			for _, index := range []int{fixture.witness, fixture.lock, len(fixture.receipt.Targets) - 2, len(fixture.receipt.Targets) - 1} {
				if err := terminalMatch(fixture.receipt.Targets[index].Native); err != nil {
					t.Fatalf("owned survivor missing before retry: %v", err)
				}
			}
			fixture.reopen(t)
			fixture.originalPlan(t)
			fixture.finish(t)
		})
	}
}

func TestTerminalResumePreservesMismatchedSurvivor(t *testing.T) {
	for _, survivor := range []string{"witness-inode", "witness-content", "lock", "selected-ancestor"} {
		t.Run(survivor, func(t *testing.T) {
			fixture := newTerminalResumeFixture(t, true)
			index := fixture.witness
			if survivor == "lock" {
				index = fixture.lock
			} else if survivor == "selected-ancestor" {
				index = len(fixture.receipt.Targets) - 2
				fixture.completeThrough(t, index-1)
			}
			target := fixture.receipt.Targets[index].Native
			original, err := os.ReadFile(fixture.receipt.Source.Witness.Path)
			if survivor != "selected-ancestor" && err != nil {
				t.Fatal(err)
			}
			backup := filepath.Join(fixture.native.rootPath, ".saved-native-survivor")
			if survivor == "witness-content" {
				if err = os.WriteFile(target.Path, []byte("changed frozen witness"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err = os.Rename(target.Path, backup); err != nil {
					t.Fatal(err)
				}
				if target.Kind == "directory" {
					err = os.Mkdir(target.Path, 0700)
				} else {
					err = os.WriteFile(target.Path, []byte("unapproved replacement"), 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			replacement, err := terminalObserve(target.Path)
			if err != nil {
				t.Fatal(err)
			}
			if _, found, err := fixture.native.resumeSource(context.Background(), fixture.approval); err == nil || !found {
				t.Fatalf("mismatched survivor accepted: found=%v err=%v", found, err)
			}
			if err = terminalMatch(replacement); err != nil {
				t.Fatalf("mismatched survivor was removed/replaced: %v", err)
			}
			if survivor == "witness-content" {
				if raw, err := os.ReadFile(target.Path); err != nil || string(raw) != "changed frozen witness" {
					t.Fatalf("mismatched witness content changed: %q %v", raw, err)
				}
				if err = os.WriteFile(target.Path, original, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if target.Kind == "file" {
					if raw, err := os.ReadFile(target.Path); err != nil || string(raw) != "unapproved replacement" {
						t.Fatalf("replacement bytes changed: %q %v", raw, err)
					}
				}
				if err = os.Remove(target.Path); err != nil {
					t.Fatal(err)
				}
				if err = os.Rename(backup, target.Path); err != nil {
					t.Fatal(err)
				}
			}
			fixture.reopen(t)
			fixture.originalPlan(t)
			fixture.finish(t)
		})
	}
}

func TestTerminalResumePreservesRecreatedCompletedObjects(t *testing.T) {
	for _, object := range []string{"database", "exact-original-witness", "retired-helper"} {
		t.Run(object, func(t *testing.T) {
			fixture := newTerminalResumeFixture(t, true)
			path := fixture.receipt.Source.Database.Path
			if object == "exact-original-witness" {
				path = fixture.receipt.Source.Witness.Path
				backup := filepath.Join(fixture.native.rootPath, ".saved-frozen-witness")
				if err := os.Rename(path, backup); err != nil {
					t.Fatal(err)
				}
				fixture.completeThrough(t, fixture.witness)
				if err := os.Rename(backup, path); err != nil {
					t.Fatal(err)
				}
				if err := terminalMatch(fixture.receipt.Source.Witness); err != nil {
					t.Fatalf("test did not restore exact original frozen inode: %v", err)
				}
			} else {
				if object == "retired-helper" {
					path = fixture.helper
				}
				if err := os.WriteFile(path, []byte("recreated completed object"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			fixture.reopen(t)
			if _, found, err := fixture.native.approvedPlan(context.Background()); err == nil || !found {
				t.Fatalf("discovery ignored recreated historical object: found=%v err=%v", found, err)
			}
			if _, found, err := fixture.native.resumeSource(context.Background(), fixture.approval); err == nil || !found {
				t.Fatalf("completed identity reused as deletion authority: found=%v err=%v", found, err)
			}
			if after, err := os.ReadFile(path); err != nil || string(after) != string(before) {
				t.Fatalf("recreated object was changed: %q %v", after, err)
			}
			if err = os.Remove(path); err != nil {
				t.Fatal(err)
			}
			fixture.originalPlan(t)
			fixture.finish(t)
		})
	}
}

func TestTerminalResumeRequiresUnchangedOriginalApproval(t *testing.T) {
	fixture := newTerminalResumeFixture(t, true)
	changed := fixture.approval
	changed.Scope = append([]ApprovedObject(nil), changed.Scope[:len(changed.Scope)-1]...)
	var err error
	changed.PlanDigest, err = PurgePlanDigest(changed)
	if err != nil {
		t.Fatal(err)
	}
	before, _, err := fixture.native.read(filepath.Base(fixture.native.receiptPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := fixture.native.resumeSource(context.Background(), changed); err == nil || !found {
		t.Fatalf("reduced/reapproved scope accepted: found=%v err=%v", found, err)
	}
	after, _, err := fixture.native.read(filepath.Base(fixture.native.receiptPath))
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("rejected approval mutated durable receipt: %v", err)
	}
	fixture.originalPlan(t)
	fixture.finish(t)
}

func TestTerminalResumeRecoversStagedProgressAfterDatabaseUnlink(t *testing.T) {
	for _, exchanged := range []bool{false, true} {
		name := "linked-next"
		if exchanged {
			name = "exchanged-old-before-parent-sync"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newTerminalResumeFixture(t, false)
			next := fixture.receipt
			next.Targets = append([]terminalTarget(nil), fixture.receipt.Targets...)
			next.Targets[fixture.database].State = terminalComplete
			next.Revision++
			prior := fixture.receipt.Publication
			next.PreviousPublication = &prior
			stage := terminalStageName(next.InstallationID, next.TransactionID, next.Revision)
			next = publishTerminalResumeReceipt(t, fixture.native, next, stage)
			if exchanged {
				fd := int(fixture.native.root.Fd())
				if err := unix.Renameat2(fd, stage, fd, filepath.Base(fixture.native.receiptPath), unix.RENAME_EXCHANGE); err != nil {
					t.Fatal(err)
				}
			}
			fixture.reopen(t)
			fixture.originalPlan(t)
			fixture.finish(t)
		})
	}
}

func TestTerminalResumeRetiresAllCompleteReceipt(t *testing.T) {
	fixture := newTerminalResumeFixture(t, true)
	var err error
	fixture.receipt, err = fixture.native.resumeFiles(context.Background(), fixture.receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range fixture.receipt.Targets {
		if target.State != terminalComplete {
			t.Fatalf("final retirement fixture has unfinished target: %+v", target)
		}
		requireTerminalResumeAbsent(t, target.Native.Path)
	}
	// The process ended after final completion publication, before receipt unlink.
	fixture.reopen(t)
	fixture.originalPlan(t)
	fixture.finish(t)
}

func TestTerminalResumeMissingReceiptPreservesOwnedSurvivors(t *testing.T) {
	fixture := newTerminalResumeFixture(t, true)
	if err := os.Remove(fixture.native.receiptPath); err != nil {
		t.Fatal(err)
	}
	if err := fixture.native.root.Sync(); err != nil {
		t.Fatal(err)
	}
	fixture.reopen(t)
	if _, found, err := fixture.native.approvedPlan(context.Background()); err != nil || found {
		t.Fatalf("missing receipt invented discovery authority: found=%v err=%v", found, err)
	}
	if result, found, err := fixture.native.resumeSource(context.Background(), fixture.approval); err != nil || found || len(result.Removed) != 0 {
		t.Fatalf("missing DB/receipt fabricated terminal success: found=%v result=%+v err=%v", found, result, err)
	}
	for _, index := range []int{fixture.witness, fixture.lock, len(fixture.receipt.Targets) - 1} {
		if err := terminalMatch(fixture.receipt.Targets[index].Native); err != nil {
			t.Fatalf("unexplained owned survivor changed: %v", err)
		}
	}
	requireTerminalResumeAbsent(t, fixture.helper)
}

func TestTerminalNativeResumeContextHoldsRealExclusiveFlock(t *testing.T) {
	fixture := newTerminalResumeFixture(t, true)
	fd, err := unix.Open(filepath.Join(fixture.native.rootPath, ".management.lock"), unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("independent native flock bypassed terminal exclusion: %v", err)
	}
	original := fixture.native.lockIdentity
	fixture.reopen(t)
	if fixture.native.lockIdentity != original {
		t.Fatal("reacquisition replaced permanent management lock")
	}
	fixture.originalPlan(t)
	fixture.finish(t)
}
