package install

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/portable/ipcpath"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

func TestPortableDirectoryIsReadOnlyAndSeparateFromLegacy(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_DATA_HOME", base)
	got, err := Directory()
	want := filepath.Join(base, "chatanium", "runtime")
	if err != nil || got != want {
		t.Fatalf("Directory = %q, %v; want %q", got, err, want)
	}
	for _, path := range []string{
		filepath.Join(base, "chatanium", Format, "demo-1"),
		filepath.Join(base, "chatanium", Format, "runtime"),
		filepath.Join(base, "chatanium", "demo-1"),
	} {
		if parent, err := anchor(path, true); err == nil {
			parent.Close()
			t.Errorf("anchor accepted alternate installation path %q", path)
		}
	}
	if _, err := os.Lstat(filepath.Join(base, "chatanium")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("path lookup or rejected anchor created storage: %v", err)
	}
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", base)
	if got, err := Directory(); err != nil || got != filepath.Join(base, ".local", "share", "chatanium", "runtime") {
		t.Fatalf("default Directory = %q, %v", got, err)
	}
	t.Setenv("XDG_DATA_HOME", "/var/lib")
	if _, err := Directory(); !errors.Is(err, ErrLegacy) {
		t.Fatalf("legacy root = %v; want LEGACY_INSTALLATION", err)
	}
	if f, err := OpenInput("/etc/chatanium/runtime.json", false); !errors.Is(err, ErrLegacy) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("legacy input = %v; want LEGACY_INSTALLATION", err)
	}
}

func TestInitializationStagingReusesPersistedIdentity(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	path, err := Directory()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := process.OwnerIdentity()
	if err != nil {
		t.Fatal(err)
	}
	fallback, err := ipcpath.FallbackBase()
	if err != nil {
		t.Fatal(err)
	}
	p := initPlan{
		Format: Format, Owner: owner, Path: path, Staging: initStaging(path), SharedParent: filepath.Dir(path), IPCFallback: fallback,
		BudgetBytes: DefaultBudgetBytes, MetadataBytes: 256 << 20, LogBytes: runtimeDiskBytes,
		Bundle: bundle.PortableManifest{
			Format: Format, Digest: hashBytes([]byte("bundle")),
			Target: bundle.PortableTarget{OS: "linux", Arch: "amd64", Backend: "systrap"},
			Engine: bundle.PortableEngine{ExecutableDigest: hashBytes([]byte("engine"))},
		},
	}
	p.PlanDigest, err = planDigest(p)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := anchor(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	stageName := filepath.Base(p.Staging)
	stage, err := privateChild(parent, stageName, true)
	if err != nil {
		t.Fatal(err)
	}
	i := &Installation{Path: p.Staging, Root: stage}
	defer i.Close()
	first, err := initializeManifest(stage, p)
	if err != nil {
		t.Fatal(err)
	}
	if !generationPattern.MatchString(first.ID) {
		t.Fatalf("installation did not receive a persistent lowercase hex ID: %q", first.ID)
	}
	i.Manifest = first
	if err := i.initializeLedger(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := i.Close(); err != nil {
		t.Fatal(err)
	}

	stage, err = privateChild(parent, stageName, false)
	if err != nil {
		t.Fatal(err)
	}
	i.Root = stage
	differentPlan := p
	differentPlan.PlanDigest = hashBytes([]byte("another plan"))
	if _, err := initializeManifest(stage, differentPlan); !errors.Is(err, store.ErrApprovalMismatch) {
		t.Fatalf("different plan opened existing staging: %v", err)
	}
	resumed, err := initializeManifest(stage, p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resumed, first) {
		t.Fatal("retry changed the staged manifest or configuration")
	}
	i.Manifest = resumed
	if err := i.initializeLedger(t.Context()); err != nil {
		t.Fatalf("retry cannot recover the original ledger: %v", err)
	}
	if err := i.Close(); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(parent, stageName, filepath.Base(path)); err != nil {
		t.Fatal(err)
	}
	installed, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer installed.Close()
	if installed.Manifest.ID != first.ID {
		t.Fatalf("reopened ID = %q, want %q", installed.Manifest.ID, first.ID)
	}
}

func TestOwnedDeleteDoesNotTraverseLinks(t *testing.T) {
	outside := t.TempDir()
	keep := filepath.Join(outside, "keep")
	if err := os.WriteFile(keep, []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	owned := t.TempDir()
	root, err := os.OpenRoot(owned)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Symlink(outside, filepath.Join(owned, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := removeOwned(root, "linked/keep"); err == nil {
		t.Fatal("deletion accepted a link as a directory")
	}
	if err := removeOwned(root, "linked"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(keep)
	if err != nil || string(data) != "retained" {
		t.Fatalf("external file changed: %q, %v", data, err)
	}
}

func TestConfigDigestMatchesPersistedRawJSON(t *testing.T) {
	original := json.RawMessage(`{ "markup" : "<a>&</a>" , "number" : 1.0 }`)
	before, err := documentDigest(original)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(Manifest{Config: original})
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	after, err := documentDigest(m.Config)
	if err != nil || after != before || hashBytes(m.Config) != before {
		t.Fatalf("persisted configuration changed its digest: before %s after %s (%v)", before, after, err)
	}
}
