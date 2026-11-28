//go:build linux

package bootstrap

import (
	"encoding/json"
	"github.com/thirdscam/chatanium/internal/host"
	legacyhost "github.com/thirdscam/chatanium/internal/legacy/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"os"
	"path/filepath"
	"testing"
)

func terminalClosureFixture(t *testing.T) (legacyhost.InstallationManifest, []legacyhost.ProvisionRecord) {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "installations")
	installation := filepath.Join(parent, "owned")
	control := filepath.Join(installation, "control")
	engine := filepath.Join(installation, "engine")
	storage := filepath.Join(installation, "storage")
	for _, path := range []string{control, engine, storage} {
		if e := os.MkdirAll(path, 0700); e != nil {
			t.Fatal(e)
		}
	}
	m := legacyhost.InstallationManifest{Paths: host.InstallationPaths{Installation: installation, Control: control, EngineRoot: engine, StorageRoot: storage, Config: filepath.Join(installation, "config.json"), BackingFile: filepath.Join(installation, "backing.xfs")}}
	records := []legacyhost.ProvisionRecord{}
	add := func(kind, path string) {
		raw, e := json.Marshal(legacyhost.ProvisionProperties{Path: path})
		if e != nil {
			t.Fatal(e)
		}
		records = append(records, legacyhost.ProvisionRecord{ProvisionIntent: legacyhost.ProvisionIntent{ID: newID(), Kind: kind, Identity: path, ProductCreated: true}, Observed: legacyhost.ObjectObservation{Identity: path, Attributes: raw}, State: "OBSERVED", CleanupState: "PENDING"})
	}
	for _, path := range []string{parent, installation, control, engine, storage} {
		add("directory", path)
	}
	for _, entry := range []struct{ kind, path string }{{"config", m.Paths.Config}, {"backing", m.Paths.BackingFile}, {"config", filepath.Join(installation, "dev-watch.lock")}} {
		if e := os.WriteFile(entry.path, []byte("owned"), 0600); e != nil {
			t.Fatal(e)
		}
		add(entry.kind, entry.path)
	}
	return m, records
}

func TestPurgeClosureSelectsOwnedInstallationAndPreservesForeignSibling(t *testing.T) {
	m, records := terminalClosureFixture(t)
	foreign := filepath.Join(filepath.Dir(m.Paths.Installation), "foreign")
	if e := os.Mkdir(foreign, 0700); e != nil {
		t.Fatal(e)
	}
	selected, e := ownedPurgeClosure(records, m)
	if e != nil {
		t.Fatal(e)
	}
	installation, parent := false, false
	for _, record := range selected {
		installation = installation || record.Identity == m.Paths.Installation
		parent = parent || record.Identity == filepath.Dir(m.Paths.Installation)
	}
	if !installation || parent {
		t.Fatalf("owned descendant closure incorrect: installation=%v parent=%v", installation, parent)
	}
	scope := []ApprovedObject{}
	for _, record := range selected {
		scope = append(scope, ApprovedObject{Kind: record.Kind, Identity: record.Identity})
	}
	if e = validateExactPurgeClosure(records, m, scope); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(foreign); e != nil {
		t.Fatal(e)
	}
}

func TestPurgeClosureRejectsUnselectedIntermediateBeforeDestruction(t *testing.T) {
	m, records := terminalClosureFixture(t)
	scope := []ApprovedObject{}
	for _, record := range records {
		if record.Identity != m.Paths.Installation {
			scope = append(scope, ApprovedObject{Kind: record.Kind, Identity: record.Identity})
		}
	}
	if e := validateExactPurgeClosure(records, m, scope); e == nil {
		t.Fatal("selected parent accepted an omitted intermediate installation")
	}
	for _, path := range []string{m.Paths.Config, m.Paths.BackingFile} {
		raw, e := os.ReadFile(path)
		if e != nil || string(raw) != "owned" {
			t.Fatalf("payload changed before rejected closure: %q %v", raw, e)
		}
	}
}

func TestPurgeClosureRetainsInstallationWithForeignChild(t *testing.T) {
	m, records := terminalClosureFixture(t)
	foreign := filepath.Join(m.Paths.Installation, "foreign")
	if e := os.WriteFile(foreign, []byte("preserved"), 0600); e != nil {
		t.Fatal(e)
	}
	selected, e := ownedPurgeClosure(records, m)
	if e != nil {
		t.Fatal(e)
	}
	for _, record := range selected {
		if record.Identity == m.Paths.Installation || record.Identity == filepath.Dir(m.Paths.Installation) {
			t.Fatal("foreign-containing ancestor selected")
		}
	}
	scope := []ApprovedObject{}
	for _, record := range records {
		scope = append(scope, ApprovedObject{Kind: record.Kind, Identity: record.Identity})
	}
	if e = validateExactPurgeClosure(records, m, scope); e == nil {
		t.Fatal("explicit inconsistent scope accepted foreign child")
	}
	raw, e := os.ReadFile(foreign)
	if e != nil || string(raw) != "preserved" {
		t.Fatalf("foreign child changed: %q %v", raw, e)
	}
}

func TestPurgeClosureRetainsFirstInitManagementAnchorLedger(t *testing.T) {
	m, records := terminalClosureFixture(t)
	for _, created := range []bool{true, false} {
		for index, path := range []string{legacyhost.ManagementRoot, filepath.Join(legacyhost.ManagementRoot, ".management.lock")} {
			properties := legacyhost.ProvisionProperties{Path: path, UID: 0, GID: 0, Mode: 0755, Dev: 1, Ino: uint64(index + 1), ReadOnly: true, ProductCreated: created}
			if index == 1 {
				properties.Mode = 0600
				properties.Digest = provision.Digest([]byte(legacyhost.ManagementMarker))
			}
			raw, e := json.Marshal(properties)
			if e != nil {
				t.Fatal(e)
			}
			// First-init and reused anchors retain their real ownership facts.
			// Neither becomes fake-completed to bypass terminal ownership checks.
			record := legacyhost.ProvisionRecord{ProvisionIntent: legacyhost.ProvisionIntent{ID: newID(), Kind: "management-anchor", Identity: path, ProductCreated: created, ExistedBefore: !created, Desired: raw}, Observed: legacyhost.ObjectObservation{Identity: path, Attributes: raw}, State: "OBSERVED", CleanupState: "PENDING"}
			records = append(records, record)
			if !sharedNetworkObject(record.Kind, record.Identity) || removableProductObject(record) {
				t.Fatal("permanent management anchor gained execution deletion authority")
			}
		}
	}
	selected, e := ownedPurgeClosure(records, m)
	if e != nil {
		t.Fatal(e)
	}
	for _, record := range selected {
		if record.Kind == "management-anchor" {
			t.Fatal("first-init permanent management anchor entered fresh purge scope")
		}
	}
	plan := PurgeApproval{InstallationID: "owned", PlanID: "approved-plan", TerminalReceiptPath: terminalReceiptPath("owned"), ManagementAnchor: legacyhost.ManagementAnchorObservation{Root: legacyhost.TerminalNativeIdentity{Path: legacyhost.ManagementRoot}, Lock: legacyhost.TerminalNativeIdentity{Path: filepath.Join(legacyhost.ManagementRoot, ".management.lock")}, Marker: legacyhost.ManagementMarker}}
	plan.PublicationProbePaths = [2]string{filepath.Join(terminalRoot, terminalStageName("owned", plan.PlanID, 0)), filepath.Join(terminalRoot, terminalStageName("owned", plan.PlanID, 1))}
	for _, record := range selected {
		plan.Scope = append(plan.Scope, ApprovedObject{Kind: record.Kind, Identity: record.Identity})
	}
	if e = validateTerminalPlacement(plan); e != nil {
		t.Fatal(e)
	}
}

func TestPurgeClosureRetainsForeignEngineChildAndControlEvidence(t *testing.T) {
	m, records := terminalClosureFixture(t)
	foreign := filepath.Join(m.Paths.EngineRoot, "foreign")
	if e := os.WriteFile(foreign, []byte("preserve"), 0600); e != nil {
		t.Fatal(e)
	}
	selected, e := ownedPurgeClosure(records, m)
	if e != nil {
		t.Fatal(e)
	}
	for _, record := range selected {
		if record.Identity == m.Paths.EngineRoot || record.Identity == m.Paths.Control || record.Identity == m.Paths.Installation {
			t.Fatalf("foreign engine or its ownership evidence selected: %s", record.Identity)
		}
	}
	scope := []ApprovedObject{}
	for _, record := range records {
		scope = append(scope, ApprovedObject{Kind: record.Kind, Identity: record.Identity})
	}
	if e = validateExactPurgeClosure(records, m, scope); e == nil {
		t.Fatal("stale exact engine scope accepted a foreign direct child")
	}
	for _, path := range []string{foreign, m.Paths.Config, m.Paths.BackingFile} {
		if _, e = os.Stat(path); e != nil {
			t.Fatal(e)
		}
	}
}

func TestPurgeClosureRejectsUnselectedOwnedEngineChildBeforeMutation(t *testing.T) {
	m, records := terminalClosureFixture(t)
	child := filepath.Join(m.Paths.EngineRoot, "owned-child")
	if e := os.WriteFile(child, []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(legacyhost.ProvisionProperties{Path: child})
	if e != nil {
		t.Fatal(e)
	}
	records = append(records, legacyhost.ProvisionRecord{ProvisionIntent: legacyhost.ProvisionIntent{ID: newID(), Kind: "config", Identity: child, ProductCreated: true}, Observed: legacyhost.ObjectObservation{Identity: child, Attributes: raw}, State: "OBSERVED", CleanupState: "PENDING"})
	scope := []ApprovedObject{}
	for _, record := range records {
		if record.Identity != child {
			scope = append(scope, ApprovedObject{Kind: record.Kind, Identity: record.Identity})
		}
	}
	if e = validateExactPurgeClosure(records, m, scope); e == nil {
		t.Fatal("selected engine directory covered an unselected owned child")
	}
	if raw, e = os.ReadFile(child); e != nil || string(raw) != "keep" {
		t.Fatalf("unselected child mutated: %q %v", raw, e)
	}
}
