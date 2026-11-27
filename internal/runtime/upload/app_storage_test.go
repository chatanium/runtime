//go:build linux

package upload

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
)

func TestGvxQuotaBackedAppUploadIsolation(t *testing.T) {
	storage := t.TempDir()
	host := runtime.HostConfig{StorageRoot: storage, ManagementDirectory: filepath.Join(storage, "app")}
	for _, path := range append(host.ModuleMountRoots(), host.ManagementDirectory, filepath.Join(host.ManagementDirectory, "uploads")) {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	config := Config{ManagementDirectory: host.ManagementDirectory, ModuleMountRoots: host.ModuleMountRoots(), Limits: runtime.Limits{UploadRecordsPerInstance: 4, UploadRecordsPerHost: 8, UploadFileNameMaxBytes: 128, UploadContentTypeMaxBytes: 128, UploadDeadline: runtime.Duration(time.Minute)}}
	store, err := New(context.Background(), config)
	if err != nil {
		t.Fatalf("app upload sibling on shared quota volume rejected: %v", err)
	}
	if err := store.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	config.ManagementDirectory = filepath.Join(storage, "persistent", "module")
	if err := os.MkdirAll(filepath.Join(config.ManagementDirectory, "uploads"), 0700); err != nil {
		t.Fatal(err)
	}
	if store, err := New(context.Background(), config); err == nil {
		store.Close(context.Background())
		t.Fatal("guest persistent storage accepted as private app spool")
	}
}
