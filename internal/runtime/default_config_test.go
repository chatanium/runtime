package runtime

import (
	"strings"
	"testing"

	"github.com/thirdscam/chatanium/internal/host"
)

func TestGvxDefaultInstallationConfigRoundTripsWithoutAuthority(t *testing.T) {
	paths := host.InstallationPaths{Installation: "/var/lib/chatanium", Control: "/var/lib/chatanium/control", StorageRoot: "/var/lib/chatanium/storage", RunRoot: "/run/chatanium/installation"}
	raw, err := DefaultInstallationConfig(strings.Repeat("a", 32), "sha256:"+strings.Repeat("b", 64), paths)
	if err != nil {
		t.Fatal(err)
	}
	config, err := DecodeConfig(raw)
	if err != nil {
		t.Fatalf("generated default does not pass production decoder: %v", err)
	}
	if len(config.Modules) != 0 || len(config.Backends) != 0 || config.Host.Network.Profile != host.NetworkNone || config.Host.Network.IPv4Pool != "" || len(config.Host.Network.Resolvers) != 0 {
		t.Fatal("cold initialization silently granted module/backend/network authority")
	}
	if config.Host.ManagementDirectory != "/var/lib/chatanium/storage/app" || config.Host.ManagementDirectory == paths.Control || config.Host.IPCRoot != "/run/chatanium/installation/instances" {
		t.Fatal("app working/upload state was not bound to the canonical quota-backed app root")
	}
	if config.Limits.UploadRecordsPerInstance != 32 || config.Limits.UploadRecordsPerHost != 256 {
		t.Fatal("app quota sizing silently reduced upload concurrency")
	}
	paths.StorageRoot = "relative-storage"
	if _, err := DefaultInstallationConfig(strings.Repeat("a", 32), "sha256:"+strings.Repeat("b", 64), paths); err == nil {
		t.Fatal("invalid installation paths received synthetic defaults")
	}
}
