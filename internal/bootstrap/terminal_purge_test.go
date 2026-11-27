//go:build linux

package bootstrap

import (
	"context"
	"encoding/json"
	"github.com/thirdscam/chatanium/internal/host"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func TestTerminalRemovalRejectsReplacedNativeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "supervisor.sqlite")
	if e := os.WriteFile(path, []byte("owned"), 0600); e != nil {
		t.Fatal(e)
	}
	native, e := terminalObserve(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(path, path+".original"); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, []byte("replacement"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = terminalDeleteTarget(terminalTarget{Native: native, State: terminalRemoving}); e == nil {
		t.Fatal("replaced native file was accepted")
	}
	raw, e := os.ReadFile(path)
	if e != nil || string(raw) != "replacement" {
		t.Fatalf("replacement was changed: %q %v", raw, e)
	}
}

func TestTerminalRemovalResumesAfterDatabaseUnlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "supervisor.sqlite")
	if e := os.WriteFile(path, []byte("source"), 0600); e != nil {
		t.Fatal(e)
	}
	native, e := terminalObserve(path)
	if e != nil {
		t.Fatal(e)
	}
	target := terminalTarget{Native: native, State: terminalRemoving}
	if e = terminalDeleteTarget(target); e != nil {
		t.Fatal(e)
	}
	// The process dies after unlink+directory fsync but before publishing COMPLETE.
	if e = terminalDeleteTarget(target); e != nil {
		t.Fatal(e)
	}
	target.State = terminalComplete
	receipt := terminalReceipt{Targets: []terminalTarget{target}}
	if e = terminalCheckAbsence(receipt); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, []byte("recreated"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = terminalCheckAbsence(receipt); e == nil {
		t.Fatal("completed database absence was reused as deletion authority")
	}
	if raw, e := os.ReadFile(path); e != nil || string(raw) != "recreated" {
		t.Fatalf("recreated database was changed: %q %v", raw, e)
	}
}

func TestTerminalDirectoryRetainsUnknownChild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control")
	if e := os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	native, e := terminalObserve(path)
	if e != nil {
		t.Fatal(e)
	}
	child := filepath.Join(path, "foreign")
	if e = os.WriteFile(child, []byte("preserve"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = terminalDeleteTarget(terminalTarget{Native: native, State: terminalRemoving}); e == nil {
		t.Fatal("unknown terminal child was accepted")
	}
	if _, e = os.Stat(child); e != nil {
		t.Fatal(e)
	}
}

func terminalPublicationFixture(t *testing.T) (*terminalNativeContext, terminalReceipt) {
	t.Helper()
	id := RuntimeInstallationID("terminal-test")
	root := filepath.Join(t.TempDir(), "management")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	c, e := acquireTerminalNativeAt(context.Background(), root, id)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	control := c.controlPath
	approval := PurgeApproval{InstallationID: id, PlanID: "terminal-plan", Scope: []ApprovedObject{{Kind: "directory", Identity: control, Action: "remove", ObservationDigest: "fixture"}}, TerminalReceiptPath: c.receiptPath}
	approval.PublicationProbePaths = [2]string{filepath.Join(c.rootPath, terminalStageName(id, approval.PlanID, 0)), filepath.Join(c.rootPath, terminalStageName(id, approval.PlanID, 1))}
	approval.ManagementAnchor = host.ManagementAnchorObservation{Root: host.TerminalNativeIdentity(c.rootIdentity), Lock: host.TerminalNativeIdentity(c.lockIdentity), Marker: host.ManagementMarker}
	approval.PlanDigest, e = PurgePlanDigest(approval)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(approval)
	if e != nil {
		t.Fatal(e)
	}
	database := host.TerminalNativeIdentity{Path: filepath.Join(control, "supervisor.sqlite"), Absent: true}
	fence := host.TerminalFence{Version: 1, InstallationID: string(id), Incarnation: "terminal-incarnation", TransactionID: approval.PlanID, ApprovalDigest: approval.PlanDigest, ApprovedPlan: raw, SourceControl: host.TerminalNativeIdentity{Path: control}, SourceDatabase: database, FrozenManifest: host.TerminalNativeIdentity{Path: filepath.Join(control, "installation.json")}, Remaining: []host.TerminalObject{{Name: "supervisor.sqlite", Native: database}}}
	receipt, e := c.receiptFromFence(fence, approval)
	if e != nil {
		t.Fatal(e)
	}
	return c, receipt
}

func terminalTestPublish(t *testing.T, c *terminalNativeContext, receipt terminalReceipt, name string) terminalReceipt {
	root := c.root
	t.Helper()
	file, native, e := terminalAnonymous(root)
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	native.Path = c.receiptPath
	receipt.Publication = native
	raw, e := json.Marshal(receipt)
	if e != nil {
		t.Fatal(e)
	}
	if e = terminalWriteAnonymous(file, raw); e != nil {
		t.Fatal(e)
	}
	if e = terminalLink(root, file, name); e != nil {
		t.Fatal(e)
	}
	if e = root.Sync(); e != nil {
		t.Fatal(e)
	}
	return receipt
}

func TestTerminalPublicationRecoversLinkedNextWithoutBackwardProgress(t *testing.T) {
	c, current := terminalPublicationFixture(t)
	root := c.root
	canonical := filepath.Base(c.receiptPath)
	current = terminalTestPublish(t, c, current, canonical)
	next := current
	next.Targets = append([]terminalTarget(nil), current.Targets...)
	next.Targets[0].State = terminalRemoving
	next.Revision++
	prior := current.Publication
	next.PreviousPublication = &prior
	stage := terminalStageName(next.InstallationID, next.TransactionID, next.Revision)
	next = terminalTestPublish(t, c, next, stage)
	// Crash after next inode is linked+synced, before RENAME_EXCHANGE.
	settled, e := c.settleStage(current)
	if e != nil {
		t.Fatal(e)
	}
	if settled.Revision != next.Revision || settled.Targets[0].State != terminalRemoving {
		t.Fatal("linked next receipt did not advance exactly once")
	}
	if _, e = os.Lstat(filepath.Join(root.Name(), stage)); !os.IsNotExist(e) {
		t.Fatalf("staging authority not reclaimed: %v", e)
	}
	observed, _, e := c.read(canonical)
	if e != nil {
		t.Fatal(e)
	}
	if !terminalPublicationMatches(observed.Publication, next.Publication) {
		t.Fatal("canonical receipt did not retain the new complete native inode")
	}
}

func TestTerminalPublicationRecoversExchangedPriorReceipt(t *testing.T) {
	c, current := terminalPublicationFixture(t)
	root := c.root
	canonical := filepath.Base(c.receiptPath)
	current = terminalTestPublish(t, c, current, canonical)
	next := current
	next.Targets = append([]terminalTarget(nil), current.Targets...)
	next.Targets[0].State = terminalRemoving
	next.Revision++
	prior := current.Publication
	next.PreviousPublication = &prior
	stage := terminalStageName(next.InstallationID, next.TransactionID, next.Revision)
	next = terminalTestPublish(t, c, next, stage)
	if e := unix.Renameat2(int(root.Fd()), stage, int(root.Fd()), canonical, unix.RENAME_EXCHANGE); e != nil {
		t.Fatal(e)
	}
	// Crash before parent fsync/old-stage unlink; recovery must make the forward
	// layout durable before removing the last previous valid authority.
	settled, e := c.settleStage(next)
	if e != nil {
		t.Fatal(e)
	}
	if settled.Revision != next.Revision {
		t.Fatal("exchanged progress moved backward")
	}
	if _, e = os.Lstat(filepath.Join(root.Name(), stage)); !os.IsNotExist(e) {
		t.Fatalf("old staging authority remains: %v", e)
	}
	observed, _, e := c.read(canonical)
	if e != nil {
		t.Fatal(e)
	}
	if !terminalPublicationMatches(observed.Publication, next.Publication) {
		t.Fatal("new canonical authority was replaced")
	}
}

func TestTerminalAccountGuardRepresentsGroupOnlyAndUnderscoreNames(t *testing.T) {
	for _, guard := range []terminalAbsenceGuard{
		{Kind: "account", Name: "_gvx_group", GID: 32123, GroupOnly: true},
		{Kind: "account", Name: "_gvx_app", UID: 32123, GID: 32124},
	} {
		if e := validateTerminalAccountGuard(guard); e != nil {
			t.Fatal(e)
		}
	}
	for _, guard := range []terminalAbsenceGuard{
		{Kind: "account", Name: "_gvx_group", UID: 32123, GID: 32124, GroupOnly: true},
		{Kind: "account", Name: "_gvx_app", GID: 32124},
		{Kind: "account", Name: "_gvx_group", GroupOnly: true},
	} {
		if e := validateTerminalAccountGuard(guard); e == nil {
			t.Fatal("invalid numeric user/group authority accepted")
		}
	}
}

func TestTerminalAccountGuardSchemaReplayPreservesGroupOnly(t *testing.T) {
	c, receipt := terminalPublicationFixture(t)
	receipt.Authority.AbsenceGuards = []host.TerminalGuard{
		{Kind: "account", RecordID: "group-observation", Name: "_gvx_group", GID: 32123, GroupOnly: true},
		{Kind: "account", RecordID: "user-observation", Name: "_gvx_app", UID: 32124, GID: 32125},
	}
	receipt.Guards = []terminalAbsenceGuard{
		{Kind: "account", Name: "_gvx_group", GID: 32123, GroupOnly: true},
		{Kind: "account", Name: "_gvx_app", UID: 32124, GID: 32125},
	}
	var e error
	receipt.SealDigest, e = terminalImmutableDigest(receipt)
	if e != nil {
		t.Fatal(e)
	}
	name := filepath.Base(c.receiptPath)
	receipt = terminalTestPublish(t, c, receipt, name)
	replayed, _, e := c.read(name)
	if e != nil {
		t.Fatal(e)
	}
	if !replayed.Guards[0].GroupOnly || replayed.Guards[0].UID != 0 || replayed.Guards[0].GID != 32123 || replayed.Guards[1].GroupOnly || replayed.Guards[1].Name != "_gvx_app" {
		t.Fatal("serialized native authority changed supported group-only/account semantics")
	}
	next := replayed
	next.Targets = append([]terminalTarget(nil), replayed.Targets...)
	next.Targets[0].State = terminalRemoving
	next.Revision++
	if _, e = c.persistProgress(replayed, next); e != nil {
		t.Fatal(e)
	}
	replayed, _, e = c.read(name)
	if e != nil {
		t.Fatal(e)
	}
	if !replayed.Guards[0].GroupOnly || replayed.Guards[0].UID != 0 || replayed.Guards[1].Name != "_gvx_app" {
		t.Fatal("forward receipt replay lost source-bound group/account shape")
	}
}
