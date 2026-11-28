//go:build linux

package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	sharedhost "github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"golang.org/x/sys/unix"
)

func testRootEntries() []gvxcontract.RootInitEntry {
	attrs := gvxcontract.RootAttrs{UID: 1001, GID: 1001, Mode: 0700}
	return []gvxcontract.RootInitEntry{{RootID: "persistent", Mountpoint: sharedhost.DataMountpoint, Disposition: "new", Target: attrs}, {RootID: "scratch", Mountpoint: sharedhost.ScratchMountpoint, Disposition: "new", Target: attrs}, {RootID: "tmp", Mountpoint: "/tmp", Disposition: "new", Target: attrs}}
}
func TestGvxStrictControlAndFiveFDTransfer(t *testing.T) {
	approved := sharedhost.LaunchSpec{ModuleID: "policy-module", ImageDigest: "record:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", InitialEgress: sharedhost.EgressNone, Entrypoint: []string{"/module"}, UID: 1001, GID: 1001, Resources: sharedhost.ResourceLimits{NanoCPUs: 1000000000, MemoryBytes: 128 << 20, Pids: 64, PersistentBytes: 1 << 20, ScratchBytes: 1 << 20, PersistentInodes: 100, ScratchInodes: 100, ControlMessageMaxBytes: 65536, LogBufferBytes: 1 << 20, LogFileMaxBytes: 1 << 20, LogRetainedFiles: 2}}
	request := approved
	request.InstanceID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := validateLaunchRequest(request, approved); err != nil {
		t.Fatal(err)
	}
	for _, increase := range []func(*sharedhost.ResourceLimits){
		func(r *sharedhost.ResourceLimits) { r.NanoCPUs++ }, func(r *sharedhost.ResourceLimits) { r.MemoryBytes++ }, func(r *sharedhost.ResourceLimits) { r.Pids++ },
		func(r *sharedhost.ResourceLimits) { r.PersistentBytes += 512 }, func(r *sharedhost.ResourceLimits) { r.ScratchBytes += 512 },
		func(r *sharedhost.ResourceLimits) { r.PersistentInodes++ }, func(r *sharedhost.ResourceLimits) { r.ScratchInodes++ },
		func(r *sharedhost.ResourceLimits) { r.ControlMessageMaxBytes++ }, func(r *sharedhost.ResourceLimits) { r.LogBufferBytes++ },
		func(r *sharedhost.ResourceLimits) { r.LogFileMaxBytes++ }, func(r *sharedhost.ResourceLimits) { r.LogRetainedFiles++ },
	} {
		changed := request
		increase(&changed.Resources)
		if err := validateLaunchRequest(changed, approved); err == nil {
			t.Fatal("worker increased a root-approved resource ceiling")
		}
	}
	changed := request
	changed.UID++
	if err := validateLaunchRequest(changed, approved); err == nil {
		t.Fatal("worker changed guest identity")
	}
	t.Run("scoped observed-unit absence", func(t *testing.T) {
		boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if err != nil {
			t.Fatal(err)
		}
		unit := testUnit("absence.service")
		unit.BootID = strings.TrimSpace(string(boot))
		pipes := []string{"pipe:[123]", "pipe:[124]", "pipe:[125]"}
		details, err := json.Marshal(UnitAbsenceDetails{UnitAbsent: true, CgroupEmpty: true, TransportPipes: pipes})
		if err != nil {
			t.Fatal(err)
		}
		evidence := CleanupEvidence{BootID: unit.BootID, Units: []sharedhost.UnitIdentity{unit}, JobsAbsent: true, ProcessesAbsent: true, TransportsClosed: true, MountsAbsent: true, OpenReferencesAbsent: true, Details: details}
		if err = validateUnitAbsenceEvidence(unit, pipes, nil, NamespacePrivate, evidence); err == nil {
			t.Fatal("missing same-boot private namespace identity accepted")
		}
		namespace := &NamespaceIdentity{Device: 4, Inode: 4026532001}
		if err = validateUnitAbsenceEvidence(unit, pipes, namespace, NamespacePrivate, evidence); err != nil {
			t.Fatal(err)
		}
		wrong := evidence
		wrong.Units = append([]sharedhost.UnitIdentity(nil), evidence.Units...)
		wrong.Units[0].InvocationID = "other"
		if err = validateUnitAbsenceEvidence(unit, pipes, namespace, NamespacePrivate, wrong); err == nil {
			t.Fatal("another invocation absence accepted")
		}
		wrong = evidence
		wrong.MountsAbsent = false
		if err = validateUnitAbsenceEvidence(unit, pipes, namespace, NamespacePrivate, wrong); err == nil {
			t.Fatal("unproven private mounts accepted")
		}
		if err = validateUnitAbsenceEvidence(unit, []string{"pipe:[126]"}, namespace, NamespacePrivate, evidence); err == nil {
			t.Fatal("different transport pipe identities accepted")
		}
		if err = validateNamespaceTransition(namespace, NamespacePrivate, &NamespaceIdentity{Device: 4, Inode: 4026532002}, NamespacePrivate); err == nil {
			t.Fatal("captured native namespace identity changed")
		}
		if err = validateNamespaceTransition(namespace, NamespacePrivate, namespace, NamespaceSharedHost); err == nil {
			t.Fatal("private namespace reclassified as shared host namespace")
		}
	})
	t.Run("fixed provisioning purposes", func(t *testing.T) {
		digest := "sha256:" + strings.Repeat("a", 64)
		container := "/owned/control/.purge-helper"
		attempt := container + "/" + strings.Repeat("b", 32)
		cases := []struct {
			kind       string
			properties ProvisionProperties
		}{
			{"config", ProvisionProperties{Path: "/owned/engine/.bundle-publication.lock", Parent: "/owned/engine", Source: "parent-record", Mode: 0600}},
			{"account", ProvisionProperties{Name: "product-preparer", Source: "group", GID: 1002}},
			{"directory", ProvisionProperties{Path: container, Parent: "/owned/control", Source: "purge-helper", Digest: digest, Mode: 0700}},
			{"directory", ProvisionProperties{Path: attempt, Parent: container, Source: "purge-helper", Digest: digest, Mode: 0700}},
			{"bundle", ProvisionProperties{Path: attempt + "/" + strings.TrimPrefix(digest, "sha256:"), Parent: attempt, Source: "purge-helper", Digest: digest}},
		}
		for _, c := range cases {
			raw, err := json.Marshal(c.properties)
			if err != nil {
				t.Fatal(err)
			}
			if err = validProvision(c.kind, raw); err != nil {
				t.Fatalf("%s fixed purpose rejected: %v", c.kind, err)
			}
		}
		for _, c := range cases {
			p := c.properties
			switch c.kind {
			case "config":
				p.Path = "/owned/engine/arbitrary"
			case "account":
				p.UID = 1002
			default:
				p.Source = "arbitrary-helper"
			}
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if err = validProvision(c.kind, raw); err == nil {
				t.Fatalf("%s arbitrary purpose accepted", c.kind)
			}
		}
	})
	for _, raw := range [][]byte{
		[]byte(`{"version":2,"operation":"register","operation":"register"}`),
		[]byte(`{"version":2,"operation":"register","bootstrap":null}`),
		[]byte(`{"version":2,"operation":"register","spec":null}`),
		[]byte(`{"version":2,"operation":"register","unknown":1}`),
		[]byte(`{"version":1,"operation":"register"}`),
		[]byte(`{"version":2,"operation":"register"} {}`),
		append([]byte(`{"version":2,"operation":"register","x":"`), 255),
	} {
		var r controlRequest
		if err := decodeControlRequest(raw, &r); err == nil {
			t.Fatalf("ambiguous control accepted: %q", raw)
		}
	}
	var nested any
	if err := gvxcontract.DecodeStrict([]byte(`[[[0]]]`), 128, 2, &nested); err == nil {
		t.Fatal("nesting bound ignored")
	}
	if err := gvxcontract.DecodeStrict([]byte(`0`), 0, 2, &nested); err == nil {
		t.Fatal("size bound ignored")
	}
	dir := t.TempDir()
	stream, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "endpoint"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	listener, err := stream.File()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	pinFD, err := unix.Open(stream.Addr().String(), unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	pin := os.NewFile(uintptr(pinFD), "endpoint-pin")
	defer pin.Close()
	var socketStat, directoryStat unix.Stat_t
	if err = unix.Fstat(pinFD, &socketStat); err != nil {
		t.Fatal(err)
	}
	if err = unix.Stat(dir, &directoryStat); err != nil {
		t.Fatal(err)
	}
	stdinRead, stdinWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdinRead.Close()
	defer stdinWrite.Close()
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdoutRead.Close()
	defer stdoutWrite.Close()
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stderrRead.Close()
	defer stderrWrite.Close()
	p := &StageProcess{Unit: testUnit("owned.service"), Stdin: stdinWrite, Stdout: stdoutRead, Stderr: stderrRead, Listener: listener, Endpoint: pin, EndpointIdentity: EndpointIdentity{Directory: dir, Path: stream.Addr().String(), DirectoryDev: uint64(directoryStat.Dev), DirectoryIno: directoryStat.Ino, SocketDev: uint64(socketStat.Dev), SocketIno: socketStat.Ino, UID: socketStat.Uid, GID: socketStat.Gid, Mode: socketStat.Mode & 07777}}
	if err = validateStageDescriptors(p); err != nil {
		t.Fatal(err)
	}
	response := controlResponse{Version: 2, Unit: &p.Unit, Init: &p.Init, EndpointIdentity: &p.EndpointIdentity}
	raw, err := marshalControl(response)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateCreateResponse(p, len(raw)); err != nil {
		t.Fatal(err)
	}
	if err = ValidateCreateResponse(p, len(raw)-1); err == nil {
		t.Fatal("complete response envelope bound ignored")
	}
	packetPath := filepath.Join(dir, "packet")
	packets, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: packetPath, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer packets.Close()
	result := make(chan error, 1)
	go func() {
		c, e := packets.AcceptUnix()
		if e != nil {
			result <- e
			return
		}
		defer c.Close()
		result <- sendPacket(c, 1<<16, response, []*os.File{p.Stdin, p.Stdout, p.Stderr, p.Listener, p.Endpoint})
	}()
	c, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: packetPath, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	raw, files, err := receivePacket(c, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFiles(files)
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	if len(files) != 5 {
		t.Fatalf("descriptor count %d", len(files))
	}
	if err = validateControlResponse(raw, "create", len(files)); err != nil {
		t.Fatal(err)
	}
	if err = validateControlResponse(raw, "wait", len(files)); err == nil {
		t.Fatal("operation/FD mismatch accepted")
	}
	for _, f := range files {
		flags, e := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
		if e != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("received FD lacks CLOEXEC: %v", e)
		}
	}
	if err = validateControlResponse(raw, "create", 6); err == nil {
		t.Fatal("extra transfer descriptor accepted")
	}
	p.Stdin, p.Stdout, p.Stderr, p.Listener, p.Endpoint = files[0], files[1], files[2], files[3], files[4]
	if err = validateStageDescriptors(p); err != nil {
		t.Fatal(err)
	}
	p.Stdin, p.Stdout = p.Stdout, p.Stdin
	if err = validateStageDescriptors(p); err == nil {
		t.Fatal("pipe access directions accepted reversed")
	}
}
func TestGvxRootConfirmationBinding(t *testing.T) {
	f := newCreateStateFixture(t, sharedhost.EgressNone)
	ctx := context.Background()
	o := f.lease.Ownership
	var roots []NativeRootIntent
	for i, r := range testRootEntries() {
		roots = append(roots, NativeRootIntent{Guest: r, StorageIntentID: "storage-" + r.RootID, Native: NativeRootIdentity{RootID: r.RootID, HostPath: filepath.Join(f.directory, r.RootID), Dev: 1, Ino: uint64(i + 1), UID: 1002, GID: 1002, Mode: 0700, Project: 7}})
	}
	manifest, err := f.journal.BeginRootIntent(ctx, o, roots)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := gvxcontract.DecodeRootManifest(manifest, 1<<16, 16)
	if err != nil {
		t.Fatal(err)
	}
	result := gvxcontract.RootInitResult{Digest: manifest.Digest, Nonce: payload.Nonce}
	var native []NativeRootIdentity
	for _, r := range roots {
		result.Results = append(result.Results, gvxcontract.RootStepResult{RootID: r.Guest.RootID, Step: 2, Observed: r.Guest.Target})
		native = append(native, r.Native)
	}
	wrong := result
	wrong.Nonce = "old-nonce"
	if err = f.journal.ConfirmRootIntent(ctx, o, wrong, native); err == nil {
		t.Fatal("stale root nonce accepted")
	}
	wrong = result
	wrong.Results = append([]gvxcontract.RootStepResult(nil), result.Results...)
	wrong.Results[1] = wrong.Results[0]
	if err = f.journal.ConfirmRootIntent(ctx, o, wrong, native); err == nil {
		t.Fatal("duplicate root accepted")
	}
	wrongNative := append([]NativeRootIdentity(nil), native...)
	wrongNative[0].Ino++
	if err = f.journal.ConfirmRootIntent(ctx, o, result, wrongNative); err == nil {
		t.Fatal("changed native root accepted")
	}
	before, err := f.journal.RootIntent(ctx, o)
	if err != nil || before.Confirmed {
		t.Fatalf("rejected result authorized COMMIT: %+v %v", before, err)
	}
	if err = f.journal.ConfirmRootIntent(ctx, o, result, native); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	after, err := f.journal.RootIntent(ctx, o)
	if err != nil || !after.Confirmed {
		t.Fatalf("confirmation not durable: %+v %v", after, err)
	}
	manifest.Payload = append(manifest.Payload, ' ')
	if _, err = gvxcontract.DecodeRootManifest(manifest, 1<<16, 16); err == nil {
		t.Fatal("root digest did not bind exact payload bytes")
	}
}

func TestGvxManagementPlanReplay(t *testing.T) {
	ctx := context.Background()
	f := newCreateStateFixture(t, sharedhost.EgressNone)
	if err := f.journal.cleanup(ctx, f.lease.Spec.InstanceID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.SetDesired(ctx, "STOPPED", strings.Repeat("d", 32)); err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{"plan_id": "configure-plan", "installation_id": f.journal.productID, "expected_active_revision": "revision"}
	canonical, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	digest := provision.DomainDigest("chatanium-configure-plan-v1", canonical)
	fields["plan_digest"] = digest
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	plan := ManagementPlanRecord{Kind: "configure", ID: "configure-plan", Digest: digest, Plan: raw, Phase: "APPROVED"}
	if err = f.journal.BeginManagementPlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if err = f.journal.SetDesired(ctx, "RUNNING", strings.Repeat("e", 32)); err == nil {
		t.Fatal("incomplete management transaction allowed RUNNING")
	}
	receipt := []byte(`{"observed":"native-receipt"}`)
	if err = f.journal.AdvanceManagementPlanState(ctx, plan.Kind, plan.ID, digest, "APPROVED", "PREPARED", receipt); err != nil {
		t.Fatal(err)
	}
	if err = f.journal.AdvanceManagementPlan(ctx, plan.Kind, plan.ID, digest, "APPROVED", "STALE"); err == nil {
		t.Fatal("stale management phase advanced")
	}
	f.reopen(t)
	saved, err := f.journal.ManagementPlan(ctx, plan.Kind, plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Phase != "PREPARED" || saved.Step != 1 || string(saved.Plan) != string(raw) || string(saved.State) != string(receipt) || saved.Snapshot.ActiveRevision != "revision" {
		t.Fatalf("management replay binding was not preserved: %+v", saved)
	}
	if err = f.journal.BeginManagementPlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	changed := plan
	changed.Plan = append(append([]byte(nil), raw...), ' ')
	if err = f.journal.BeginManagementPlan(ctx, changed); err == nil {
		t.Fatal("same digest adopted different exact approved bytes")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	evidence := CleanupEvidence{BootID: strings.TrimSpace(string(boot)), JobsAbsent: true, ProcessesAbsent: true, TransportsClosed: true, MountsAbsent: true, OpenReferencesAbsent: true, QuotaReclaimed: true}
	if err = f.journal.CompleteManagementPlan(ctx, plan.Kind, plan.ID, digest, "PREPARED", evidence); err != nil {
		t.Fatal(err)
	}
	saved, err = f.journal.ManagementPlan(ctx, plan.Kind, plan.ID)
	if err != nil || saved.Phase != "COMMITTED" {
		t.Fatalf("management completion missing: %+v %v", saved, err)
	}
	var held int
	if err = f.journal.db.QueryRowContext(ctx, "SELECT count(*) FROM generation_references WHERE claim=?", managementClaim(saved)).Scan(&held); err != nil || held != 0 {
		t.Fatalf("transaction retained released references: %d %v", held, err)
	}
	if err = f.journal.SetDesired(ctx, "RUNNING", strings.Repeat("f", 32)); err != nil {
		t.Fatal(err)
	}
}

func TestImagePreparationInputPreservesOriginalIntent(t *testing.T) {
	ctx := context.Background()
	f := newCreateStateFixture(t, sharedhost.EgressNone)
	root := filepath.Join(f.directory, "storage")
	if err := f.journal.updateInstallation(ctx, func(m *InstallationManifest, _ *sql.Tx) error { m.Paths.StorageRoot = root; return nil }); err != nil {
		t.Fatal(err)
	}
	job := strings.Repeat("c", 32)
	input := provision.ApprovedImageInput{JobID: job, SourceKind: "registry", SourceRef: "registry.example/module@sha256:" + strings.Repeat("d", 64), CredentialRef: "credential-" + job, ModuleID: "installed-module", ConfigRevision: "config-original", ApprovalRevision: "approval-original", Platform: "linux/amd64", Limits: provision.PrepareLimits{NanoCPUs: 1000000000, MemoryBytes: 128 << 20, Tasks: 8, InputBytes: 1 << 20, ExpandedBytes: 2 << 20, OutputBytes: 1 << 20, Inodes: 1024, JSONBytes: 1 << 20, DescriptorCount: 64, IndexDepth: 8, Deadline: time.Minute}}
	space := ImageSpace{JobID: job, Source: filepath.Join(root, "images", job), Cache: filepath.Join(root, "prepared", job), Work: filepath.Join(root, "preparation", job)}
	properties := ProvisionProperties{Name: job, Path: space.Source, Source: space.Work, Target: space.Cache, Revision: "bundle", ImageSpace: &space, PrepareLimits: &input.Limits, ApprovedImageInput: &input, ProductCreated: true}
	raw, err := json.Marshal(properties)
	if err != nil {
		t.Fatal(err)
	}
	recordID := strings.Repeat("d", 32)
	if err = f.journal.BeginProvision(ctx, ProvisionIntent{ID: recordID, Kind: "image", Identity: job, ProductCreated: true, Desired: raw}); err != nil {
		t.Fatal(err)
	}
	missing := properties
	missing.ApprovedImageInput = nil
	missingRaw, err := json.Marshal(missing)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.journal.ObserveProvision(ctx, recordID, ObjectObservation{Identity: job, Attributes: missingRaw}); err == nil {
		t.Fatal("observation discarded original input")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	proof := CleanupEvidence{BootID: strings.TrimSpace(string(boot)), JobsAbsent: true, ProcessesAbsent: true, TransportsClosed: true, MountsAbsent: true, OpenReferencesAbsent: true, QuotaReclaimed: true}
	if err = f.journal.CompleteProvisionCleanup(ctx, recordID, proof); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	saved, err := f.journal.ImagePreparationInput(ctx, job)
	if err != nil || saved != input {
		t.Fatalf("completed original acquisition history was not preserved: %+v %v", saved, err)
	}
	changed := input
	changed.Limits.MemoryBytes++
	properties.ApprovedImageInput = &changed
	properties.PrepareLimits = &changed.Limits
	raw, err = json.Marshal(properties)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.journal.BeginProvision(ctx, ProvisionIntent{ID: strings.Repeat("e", 32), Kind: "image", Identity: job, ProductCreated: true, Desired: raw}); err == nil {
		t.Fatal("same job adopted a different approved input")
	}
	changed = input
	changed.CredentialRef = "/root/.docker/config.json"
	properties.ApprovedImageInput = &changed
	properties.PrepareLimits = &changed.Limits
	raw, err = json.Marshal(properties)
	if err != nil {
		t.Fatal(err)
	}
	if err = validProvision("image", raw); err == nil {
		t.Fatal("credential auth path accepted as opaque reference")
	}
	if err = validProvision("development-worker", raw); err == nil {
		t.Fatal("original acquisition authority leaked to another ledger kind")
	}
}

func TestResumeInitializationPreservesApprovedPendingRevision(t *testing.T) {
	ctx := context.Background()
	f := newCreateStateFixture(t, sharedhost.EgressNone)
	if err := f.journal.cleanup(ctx, f.lease.Spec.InstanceID, true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.journal.db.ExecContext(ctx, "UPDATE runtime_epochs SET state='REVOKED'"); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.updateInstallation(ctx, func(m *InstallationManifest, _ *sql.Tx) error {
		m.State = "PROVISIONING"
		m.DesiredRunState = "STOPPED"
		m.ActiveRevision = ""
		m.PendingRevision = ""
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	baseConfig := []byte(`{"modules":[]}`)
	planID := "initialization-replay"
	fields := map[string]any{"plan_id": planID, "installation_id": f.journal.productID, "bundle_digest": "bundle", "base_config": baseConfig, "modules": []any{}}
	canonical, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	digest := provision.DomainDigest("chatanium-init-plan-v1", canonical)
	fields["plan_digest"] = digest
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.journal.BeginManagementPlan(ctx, ManagementPlanRecord{Kind: "init", ID: planID, Digest: digest, Plan: raw, Phase: "APPROVED"}); err != nil {
		t.Fatal(err)
	}
	base := RevisionRecord{ID: planID, Config: baseConfig, ConfigDigest: provision.Digest(baseConfig), BundleDigest: "bundle", PublicProfile: sharedhost.NetworkNone}
	if err = f.journal.SetPendingRevision(ctx, base); err != nil {
		t.Fatal(err)
	}
	finalConfig := []byte(`{"reviewed":true}`)
	final := RevisionRecord{ID: "initialization-final", Config: finalConfig, ConfigDigest: provision.Digest(finalConfig), BundleDigest: "bundle", PublicProfile: sharedhost.NetworkNone}
	if err = f.journal.SetPendingRevision(ctx, final); err != nil {
		t.Fatal(err)
	}
	replacement := final
	replacement.ID = "different-final"
	if err = f.journal.SetPendingRevision(ctx, replacement); err == nil {
		t.Fatal("initialization final pending identity was rebound")
	}
	if err = f.journal.RequireRecovery(ctx, "initialization cleanup is incomplete"); err != nil {
		t.Fatal(err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	evidence := CleanupEvidence{BootID: strings.TrimSpace(string(boot)), JobsAbsent: true, ProcessesAbsent: true, TransportsClosed: true, MountsAbsent: true, OpenReferencesAbsent: true, QuotaReclaimed: true}
	if err = f.journal.CompleteRecovery(ctx, evidence); err == nil {
		t.Fatal("normal recovery accepted initialization without active release")
	}
	if err = f.journal.ResumeInitialization(ctx, planID, provision.Digest([]byte("different approval")), evidence); err == nil {
		t.Fatal("initialization resumed under a different approval")
	}
	if err = f.journal.ResumeInitialization(ctx, planID, digest, evidence); err != nil {
		t.Fatal(err)
	}
	m, err := f.journal.Installation(ctx)
	if err != nil || m.State != "PROVISIONING" || m.ActiveRevision != "" || m.PendingRevision != final.ID {
		t.Fatalf("initialization pending state was not preserved: %+v %v", m, err)
	}
	transaction, err := f.journal.ManagementPlan(ctx, "init", planID)
	if err != nil || transaction.Phase != "APPROVED" {
		t.Fatalf("recovery invented prepared approval: %+v %v", transaction, err)
	}
	if err = f.journal.RequireRecovery(ctx, "initialization cleanup is incomplete"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.journal.db.ExecContext(ctx, "INSERT INTO metadata VALUES(?,?)", "retiring_generation:bundle", "1"); err != nil {
		t.Fatal(err)
	}
	if err = f.journal.ResumeInitialization(ctx, planID, digest, evidence); err == nil {
		t.Fatal("initialization resurrected a retired generation")
	}
}
