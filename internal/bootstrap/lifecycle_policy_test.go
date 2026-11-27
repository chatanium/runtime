package bootstrap

import (
	"context"
	"github.com/thirdscam/chatanium/internal/host"
	"os"
	"path/filepath"
	"testing"
)

func TestServiceRestartConsumesStoppedIntent(t *testing.T) {
	desired, admit, e := runIntent(Service, "STOPPED")
	if e != nil || desired != "STOPPED" || admit {
		t.Fatalf("service restart changed stopped intent: %q %v %v", desired, admit, e)
	}
	desired, admit, e = runIntent(Foreground, "STOPPED")
	if e != nil || desired != "RUNNING" || !admit {
		t.Fatalf("explicit foreground did not create start intent: %q %v %v", desired, admit, e)
	}
	if _, _, e = runIntent(Service, "UNKNOWN"); e == nil {
		t.Fatal("unknown durable intent was admitted")
	}
}
func TestRemovalCannotAdoptExternalObject(t *testing.T) {
	observation := host.ObjectObservation{Identity: "owned", Attributes: []byte(`{"path":"/owned","dev":1,"ino":2}`)}
	sum, e := ObjectObservationDigest(observation)
	if e != nil {
		t.Fatal(e)
	}
	record := host.ProvisionRecord{ProvisionIntent: host.ProvisionIntent{ID: "object", Kind: "directory", Identity: "owned", ProductCreated: true}, Observed: observation, State: "OBSERVED", CleanupState: "PENDING"}
	approval := ApprovedObject{Kind: "directory", Identity: "owned", Action: "remove", ObservationDigest: sum}
	if e = authorizeRemoval(record, approval); e != nil {
		t.Fatal(e)
	}
	record.ProductCreated = false
	record.ExistedBefore = true
	if e = authorizeRemoval(record, approval); e == nil {
		t.Fatal("approval converted an existing foreign object into product ownership")
	}
	record.ProductCreated = true
	record.ExistedBefore = false
	record.Observed.Attributes = []byte(`{"path":"/owned","dev":1,"ino":3}`)
	if e = authorizeRemoval(record, approval); e == nil {
		t.Fatal("changed inode accepted stale removal approval")
	}
}
func TestCompletedRemovalRejectsReappearedPath(t *testing.T) {
	for _, kind := range []string{"config", "backing", "bundle", "directory"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "reappeared")
			if kind == "bundle" || kind == "directory" {
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
			} else if e := os.WriteFile(path, []byte("foreign replacement"), 0600); e != nil {
				t.Fatal(e)
			}
			record := host.ProvisionRecord{ProvisionIntent: host.ProvisionIntent{Kind: kind, Identity: path, ProductCreated: true}, State: "OBSERVED", CleanupState: "COMPLETE", Observed: host.ObjectObservation{Identity: path, Attributes: provisionJSON(host.ProvisionProperties{Path: path})}}
			if e := completedObjectAbsent(record); e == nil {
				t.Fatal("completed receipt authorized a reappeared object")
			}
			if _, e := os.Lstat(path); e != nil {
				t.Fatalf("replacement changed: %v", e)
			}
		})
	}
}
func TestMountedStorageRootRequiresExactVolumeAssociation(t *testing.T) {
	m := host.InstallationManifest{Paths: host.InstallationPaths{StorageRoot: "/owned-volume"}, Backing: host.BackingIdentity{Dev: 1, Ino: 2, SizeBytes: 4096, XFSUUID: "owned-xfs"}}
	p := host.ProvisionProperties{Path: m.Paths.StorageRoot, Dev: 3, Ino: 4}
	record := host.ProvisionRecord{ProvisionIntent: host.ProvisionIntent{Kind: "directory", Identity: m.Paths.StorageRoot}, State: "OBSERVED"}
	record.Observed.Attributes = provisionJSON(p)
	if insideStorage(record, m) {
		t.Fatal("host mountpoint was classified as mounted contents")
	}
	volume := m.Backing
	p.Volume = &volume
	record.Observed.Attributes = provisionJSON(p)
	if !insideStorage(record, m) {
		t.Fatal("exact mounted native volume root not classified")
	}
	volume.XFSUUID = "other-xfs"
	record.Observed.Attributes = provisionJSON(p)
	if insideStorage(record, m) {
		t.Fatal("foreign backing association accepted")
	}
}
func TestUninstallPreservesBorrowedLauncher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "preinstalled-launcher")
	original := []byte("preexisting protected launcher")
	if e := os.WriteFile(path, original, 0600); e != nil {
		t.Fatal(e)
	}
	m := host.InstallationManifest{RuntimeInstallationID: "installation", Paths: host.InstallationPaths{Launcher: path}}
	borrowed := host.ProvisionRecord{ProvisionIntent: host.ProvisionIntent{ID: "borrowed", Kind: "config", Identity: path, ExistedBefore: true, ProductCreated: false}, State: "OBSERVED", CleanupState: "PENDING", Observed: host.ObjectObservation{Identity: path, Attributes: provisionJSON(host.ProvisionProperties{Path: path})}}
	if uninstallRemovable(borrowed, m) {
		t.Fatal("ordinary uninstall selected a preinstalled borrowed launcher for removal")
	}
	if e := removeRecorded(context.Background(), nil, borrowed, host.CleanupEvidence{}); e == nil {
		t.Fatal("central removal primitive accepted borrowed ownership")
	}
	actual, e := os.ReadFile(path)
	if e != nil || string(actual) != string(original) {
		t.Fatalf("borrowed launcher changed: %q %v", actual, e)
	}
	replacement := borrowed
	replacement.ExistedBefore = false
	replacement.ProductCreated = true
	if !uninstallRemovable(replacement, m) {
		t.Fatal("explicitly replaced product-created launcher not eligible")
	}
}
