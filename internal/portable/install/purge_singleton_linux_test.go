package install

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

func TestPendingPurgeDoesNotRemoveReplacementSingleton(t *testing.T) {
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	path, err := Directory()
	must(err)
	parent, err := anchor(path, true)
	must(err)
	defer parent.Close()
	leaf := filepath.Base(path)
	must(parent.Mkdir(leaf, 0700))
	nativeID, err := maintenanceDirectoryIdentity(parent, leaf)
	must(err)
	owner, err := process.OwnerIdentity()
	must(err)
	// A crash after removing the last ledger file leaves only the parent receipt.
	scope := purgeScope{
		Format: Format, Root: path, RootNativeID: nativeID, ParentRetained: parent.Name(), Owner: owner,
		ConfigDigest: hashBytes([]byte("config")), ManifestDigest: hashBytes([]byte("manifest")),
		Ledger: store.PurgePlan{
			InstallationIdentity: store.InstallationIdentity{
				ID: strings.Repeat("a", 32), Owner: owner, Target: "linux/amd64/systrap",
				BundleDigest: hashBytes([]byte("bundle")), EngineDigest: hashBytes([]byte("engine")),
			},
		},
		Finalize:        []string{store.DatabaseName, manifestName, ownerLock, purgeIntent, ".writing-" + purgeIntent, "."},
		TerminalReceipt: purgeTerminalName(path),
	}
	backupID := strings.Repeat("b", 32)
	scope.Ledger.Backups = []store.Backup{{ID: backupID, InstallationIdentity: scope.Ledger.InstallationIdentity}}
	scope.Ledger.Digest, err = planDigest(scope.Ledger)
	must(err)
	raw, err := json.Marshal(scope)
	must(err)
	must(writeNew(parent, scope.TerminalReceipt, raw))
	approved, err := planDigest(scope)
	must(err)
	confirm := func(_ string, value any, digest string) error {
		retained := value.(purgeScope).Ledger.Backups
		if len(retained) != 1 || retained[0].ID != backupID || retained[0].InstallationIdentity != scope.Ledger.InstallationIdentity {
			t.Fatal("purge receipt lost the backup's installation identity")
		}
		if digest != approved {
			t.Fatalf("unexpected purge scope: %s", digest)
		}
		return nil
	}

	must(parent.Rename(leaf, "original"))
	must(parent.Mkdir(leaf, 0700))
	if err := Purge(context.Background(), path, confirm); !errors.Is(err, store.ErrApprovalMismatch) {
		t.Fatalf("stale receipt for a different directory: %v", err)
	}
	must(parent.Remove(leaf)) // The new root was not deleted.
	must(parent.Rename("original", leaf))
	must(Purge(context.Background(), path, confirm))
	for _, name := range []string{leaf, scope.TerminalReceipt} {
		if _, err := parent.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("resumed purge left %q: %v", name, err)
		}
	}
}
