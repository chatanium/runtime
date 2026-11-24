package sandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/portable/images"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

func TestLaunchMatchRequiresExactReviewedProjection(t *testing.T) {
	approved := host.LaunchSpec{ModuleID: "m", ImageDigest: "record:sha256:test", InitialEgress: host.EgressPublicInternet, UID: 1000, GID: 1000, Entrypoint: []string{"/module"}, ConfigRevision: "config", ApprovalRevision: "review", Resources: host.ResourceLimits{PersistentBytes: 16 << 20}}
	request := approved
	request.InstanceID = strings.Repeat("a", 32)
	if !sameLaunch(approved, request) {
		t.Fatal("new instance ID should preserve the authorized projection")
	}
	for _, mutate := range []func(*host.LaunchSpec){
		func(r *host.LaunchSpec) { r.Entrypoint = []string{"/other"} },
		func(r *host.LaunchSpec) { r.InitialEgress = host.EgressNone },
		func(r *host.LaunchSpec) { r.ImageDigest = "record:sha256:other" },
		func(r *host.LaunchSpec) { r.Resources.PersistentBytes += 16 << 20 },
		func(r *host.LaunchSpec) { r.ApprovalRevision = "old" },
	} {
		different := request
		mutate(&different)
		if sameLaunch(approved, different) {
			t.Fatalf("accepted changed projection: %+v", different)
		}
	}
}

func TestBridgeBootstrapCannotSupplyLaunchEnvironment(t *testing.T) {
	id := strings.Repeat("a", 32)
	roots, err := gvxcontract.NewPortableRootManifest(gvxcontract.RootBinding{RuntimeInstallationID: id, EpochID: id, InstanceID: id, IntentID: id, Nonce: id},
		gvxcontract.PortableRootLimits{MaxPIDs: 16, PersistentBytes: 16 << 20, ScratchBytes: 16 << 20}, 1000, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	approved := Module{Spec: host.LaunchSpec{UID: 1000, GID: 1000, Entrypoint: []string{"/module"}, Args: []string{"approved"}}, Image: images.Generation{Entrypoint: []string{"/image"}, Cmd: []string{"image-default"}, ImageEnv: []string{"SOURCE=image"}}}
	bootstrap := []string{"FLEXMODULE_PLUGIN=CHATANIUM_FOREVER", "PLUGIN_PROTOCOL_VERSIONS=2", "PLUGIN_MULTIPLEX_GRPC=true", "PLUGIN_CLIENT_CERT=test", "PLUGIN_UNIX_SOCKET_DIR=" + guestSocketDir, "PLUGIN_UNIX_SOCKET_GROUP=1000"}
	init, err := bridgeInit(approved, bootstrap, roots, 16<<10)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(init.Argv, []string{"/module", "approved"}) || init.Env[0] != "SOURCE=image" {
		t.Fatalf("persistent reviewed launch was not used: %+v", init)
	}
	if _, err = bridgeInit(approved, append(bootstrap, "SOURCE=worker"), roots, 16<<10); err == nil {
		t.Fatal("accepted a worker overlay")
	}
	t.Run("resolved CMD-only image", func(t *testing.T) {
		command := []string{"/module", "--serve"}
		cmdOnly := approved
		cmdOnly.Spec.Entrypoint, cmdOnly.Spec.Args = command, nil
		cmdOnly.Image.Entrypoint, cmdOnly.Image.Cmd = nil, command
		init, err := bridgeInit(cmdOnly, bootstrap, roots, 16<<10)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(init.Argv, command) {
			t.Fatalf("bridge reapplied image defaults: %q; want %q", init.Argv, command)
		}

		cmdOnly.Spec.Entrypoint = nil
		if _, err := bridgeInit(cmdOnly, bootstrap, roots, 16<<10); err == nil {
			t.Fatal("bridge accepted an empty reviewed command")
		}
	})
	approved.Image.ImageEnv = append(approved.Image.ImageEnv, "PLUGIN_CLIENT_CERT=forged")
	if _, err = bridgeInit(approved, bootstrap, roots, 16<<10); err == nil {
		t.Fatal("accepted trusted bootstrap from image environment")
	}
}

func TestDiagnosticRotationRespectsAggregateMaximum(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := drainLogs(root, bytes.NewBufferString("0123456789abc"), 4, 2); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"log.0": "c", "log.1": "89ab"} {
		got, err := root.ReadFile(name)
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
	if _, err := root.Lstat("log.2"); !os.IsNotExist(err) {
		t.Fatalf("retention did not remove oldest log: %v", err)
	}
}

func TestPersistentBackingRequiresKnownIdentity(t *testing.T) {
	volume := store.Volume{Initialized: true, NativeID: "verified", MaxBytes: 16 << 20}
	if err := validateVolume(volume, store.PersistentObservation{}); err == nil {
		t.Fatal("would replace a missing retained backing")
	}
	actual := store.PersistentObservation{Exists: true, NativeID: "verified", SizeBytes: 16 << 20}
	if err := validateVolume(volume, actual); err != nil {
		t.Fatal(err)
	}
	actual.SizeBytes += 16 << 20
	if err := validateVolume(volume, actual); err == nil {
		t.Fatal("would reopen oversized backing")
	}
	actual.SizeBytes = 16 << 20
	volume.NativeID = ""
	volume.Initialized = false
	if err := validateVolume(volume, actual); err == nil {
		t.Fatal("would parse unrecognized host backing")
	}
}

func TestProvisionalMoveNeverReplacesRetainedBacking(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile(provisionalLeaf, nil, 0600); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join("volumes", "approved.ext4")
	if err := root.Mkdir("volumes", 0700); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile(final, []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := moveExclusive(root, provisionalLeaf, final); err == nil {
		t.Fatal("provisional publication clobbered a retained name")
	}
	raw, err := root.ReadFile(final)
	if err != nil || string(raw) != "retained" {
		t.Fatalf("retained backing was altered: %q, %v", raw, err)
	}
	stage, err := root.Stat(provisionalLeaf)
	if err != nil || stage.Size() != 0 {
		t.Fatalf("rejected publish lost the staged inode: %v", err)
	}
	if err := root.Remove(final); err != nil {
		t.Fatal(err)
	}
	if err := moveExclusive(root, provisionalLeaf, final); err != nil {
		t.Fatal(err)
	}
	published, err := root.Stat(final)
	if err != nil || !os.SameFile(stage, published) {
		t.Fatalf("publication did not preserve the recorded native inode: %v", err)
	}
}

func TestReclaimRequiresProvisionalIdentityNotFileFormat(t *testing.T) {
	top, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(top)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, path := range []string{"work", "volumes"} {
		if err := process.EnsurePrivateDir(filepath.Join(top, path)); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join("volumes", "new.ext4")
	if err := root.WriteFile(path, []byte("partial format"), 0600); err != nil {
		t.Fatal(err)
	}
	actual, err := observeVolume(root, path)
	if err != nil || !actual.Exists {
		t.Fatalf("observe provisional candidate: %v", err)
	}
	run := store.Run{Key: store.RunKey{ID: "origin"}, InstancePath: "work",
		Persistent: store.Volume{Path: path, NativeID: actual.NativeID, CreationRunID: "different-run"}}
	if err := reclaimPersistent(root, run, nil); err == nil {
		t.Fatal("reclaimed a backing from another run")
	}
	run.Persistent.CreationRunID = run.Key.ID
	run.Persistent.Initialized = true
	if err := reclaimPersistent(root, run, nil); err == nil {
		t.Fatal("reclaimed a retained backing")
	}
	run.Persistent.Initialized = false
	if err := reclaimPersistent(root, run, nil); err != nil {
		t.Fatal(err)
	}
	reclaimed, err := observeVolume(root, filepath.Join(run.InstancePath, reclaimLeaf))
	if err != nil || reclaimed != actual {
		t.Fatalf("rollback lost the owned provisional identity: %+v, %v", reclaimed, err)
	}
}
