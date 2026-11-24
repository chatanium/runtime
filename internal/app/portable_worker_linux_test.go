package app

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	plugin "github.com/hashicorp/go-plugin"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/session"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	portableGuestFixture  = "CHATANIUM_TEST_PORTABLE_GUEST"
	portableConfigFixture = `{"fixture":9007199254740993}`
)

func portableScope() []*wire.ResourceScope {
	return []*wire.ResourceScope{{SelectorKind: &wire.ResourceScope_Selector{Selector: &wire.ResourceSelector{}}}}
}

func portableManifest() *wire.ModuleManifest {
	return &wire.ModuleManifest{ProtocolMajor: core.ProtocolMajor, Name: "portable-guest-fixture",
		RequiredCapabilities: []*wire.CapabilityRequest{{Name: core.CapabilityConfigRead, ResourceScopes: portableScope()}}}
}

func appendStage(path, stage string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	_, err = io.WriteString(f, stage+"\n")
	return errors.Join(err, f.Close())
}

type portableModule struct{ trace string }

func (m portableModule) GetManifest(context.Context) (*wire.ModuleManifest, error) {
	return portableManifest(), appendStage(m.trace, "manifest")
}

func (portableModule) GetStatus(context.Context) (*wire.Status, error) {
	return &wire.Status{Readiness: wire.Readiness_READINESS_READY}, nil
}

func (m portableModule) OnStage(_ context.Context, req *wire.StageRequest) error {
	switch req.Stage {
	case wire.Stage_STAGE_INIT:
		if req.InitContext == nil || req.InitContext.PersistentDirectory != host.DataMountpoint || req.InitContext.ScratchDirectory != host.ScratchMountpoint {
			return errors.New("portable guest mount paths changed")
		}
		return appendStage(m.trace, "init")
	case wire.Stage_STAGE_START:
		return appendStage(m.trace, "start")
	case wire.Stage_STAGE_DRAIN:
		return appendStage(m.trace, "drain")
	case wire.Stage_STAGE_STOP:
		return appendStage(m.trace, "stop")
	}
	return errors.New("unexpected module stage")
}

func (portableModule) OnEvent(context.Context, *wire.EventEnvelope) error { return nil }

func TestPortableGuestFixtureProcess(t *testing.T) {
	trace := os.Getenv(portableGuestFixture)
	if trace == "" {
		return
	}
	module, err := core.NewModulePlugin(context.Background(), portableModule{trace}, func(ctx context.Context, conn grpc.ClientConnInterface) error {
		config, err := core.NewCoreClient(conn, core.JSONLimits{MaxBytes: 1024, MaxDepth: 16})
		if err != nil {
			return err
		}
		actual, err := config.GetConfig(ctx)
		if err != nil {
			return err
		}
		if !bytes.Equal(actual.Json, []byte(portableConfigFixture)) {
			return errors.New("approved core configuration changed in transit")
		}
		return nil
	}, core.TransportLimits{MaxReceiveBytes: 1 << 20, MaxSendBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	plugin.Serve(module.ServeConfig())
}

// The fixture substitutes only the GVX supervisor backend. The worker,
// supervisor session, go-plugin TLS, mux, helper and module hooks are real.
type portableFixtureBackend struct {
	owner, epoch, guestDir, trace, digest string
	decl                                  []byte
	mu                                    sync.Mutex
	id                                    string
	child                                 *os.Process
	childDone                             chan struct{}
}

func (b *portableFixtureBackend) Manifest(_ context.Context, digest string) ([]byte, error) {
	if digest != b.digest {
		return nil, errors.New("unknown fixture digest")
	}
	return b.decl, nil
}

func (b *portableFixtureBackend) Acquire(_ context.Context, spec host.LaunchSpec) (host.Lease, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.id != "" || spec.InstanceID == "" || spec.ImageDigest != b.digest || spec.Resources.Pids != 64 || spec.Resources.PersistentInodes != 0 {
		return host.Lease{}, errors.New("unapproved fixture launch")
	}
	b.id = spec.InstanceID
	return host.Lease{Ownership: host.Ownership{RuntimeInstallationID: b.owner, InstallationID: b.owner,
		EpochID: b.epoch, InstanceID: spec.InstanceID}, Spec: spec, Topology: host.NetworkNone, SandboxUID: spec.UID, SandboxGID: spec.GID}, nil
}

func (b *portableFixtureBackend) Open(ctx context.Context, id string, env []string) ([]byte, io.ReadWriteCloser, error) {
	b.mu.Lock()
	if id != b.id || b.child != nil {
		b.mu.Unlock()
		return nil, nil, errors.New("wrong fixture instance")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPortableGuestFixtureProcess$")
	for _, entry := range env {
		switch k, v, _ := strings.Cut(entry, "="); k {
		case "PLUGIN_UNIX_SOCKET_DIR":
			if v != session.GuestSocketDir {
				b.mu.Unlock()
				return nil, nil, errors.New("guest socket path was not fixed")
			}
			entry = k + "=" + b.guestDir
		case "PLUGIN_UNIX_SOCKET_GROUP":
			entry = k + "=" + strconv.Itoa(os.Getegid())
		}
		cmd.Env = append(cmd.Env, entry)
	}
	cmd.Env = append(cmd.Env, portableGuestFixture+"="+b.trace)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		b.mu.Unlock()
		return nil, nil, err
	}
	if err = cmd.Start(); err != nil {
		b.mu.Unlock()
		return nil, nil, err
	}
	b.child, b.childDone = cmd.Process, make(chan struct{})
	done := b.childDone
	b.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = cmd.Process.Kill() })
	defer stop()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	go func() { _ = cmd.Wait(); close(done) }()
	if err != nil {
		return nil, nil, err
	}
	fields := strings.Split(line, "|")
	if len(fields) != 7 || filepath.Dir(fields[3]) != b.guestDir {
		return nil, nil, errors.New("fixture did not serve its real Unix handshake")
	}
	var dial net.Dialer
	conn, err := dial.DialContext(ctx, "unix", fields[3])
	if err != nil {
		return nil, nil, err
	}
	fields[3] = session.GuestSocketDir + "/" + filepath.Base(fields[3])
	return []byte(strings.Join(fields, "|")), conn, nil
}

func (b *portableFixtureBackend) SetEgress(_ context.Context, id string, policy host.EgressPolicy) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if id != b.id || policy != host.EgressNone {
		return errors.New("fixture egress used a different instance or policy")
	}
	before, err := os.ReadFile(b.trace)
	if err != nil || string(before) != "manifest\n" {
		return errors.New("egress applied before authenticated GetManifest or after INIT")
	}
	return appendStage(b.trace, "egress")
}

func (b *portableFixtureBackend) Wait(ctx context.Context, id string) (host.ProcessExit, error) {
	b.mu.Lock()
	done := b.childDone
	match := id == b.id
	b.mu.Unlock()
	if !match || done == nil {
		return host.ProcessExit{}, errors.New("fixture child absent")
	}
	select {
	case <-ctx.Done():
		return host.ProcessExit{}, ctx.Err()
	case <-done:
		return host.ProcessExit{Kind: "exit"}, nil
	}
}

func (b *portableFixtureBackend) Terminate(ctx context.Context, id string) error {
	b.mu.Lock()
	child, match := b.child, id == b.id
	b.mu.Unlock()
	if !match {
		return errors.New("fixture termination used a different instance")
	}
	if child != nil {
		_ = child.Kill()
		_, err := b.Wait(ctx, id)
		return err
	}
	return nil
}

func (b *portableFixtureBackend) Release(ctx context.Context, id string) error {
	if _, err := b.Wait(ctx, id); err != nil {
		return err
	}
	return appendStage(b.trace, "release")
}

func (*portableFixtureBackend) Reconcile(context.Context) error { return nil }

func TestPortableWorkerRunsAuthenticatedModuleAndDrains(t *testing.T) {
	dir, err := os.MkdirTemp("", "ct-w-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	creds, err := session.NewCredentials("portable-test-epoch")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := filepath.Join(dir, "ipc")
	b := &portableFixtureBackend{owner: "portable-fixture", epoch: creds.Epoch, guestDir: filepath.Join(dir, "guest"),
		trace: filepath.Join(dir, "stages"), digest: "record:sha256:" + strings.Repeat("a", 64)}
	b.decl, err = protojson.Marshal(portableManifest())
	if err != nil {
		t.Fatal(err)
	}
	storage := filepath.Join(dir, "storage")
	config := runtime.DefaultPortableConfig(b.owner, "sha256:"+strings.Repeat("b", 64), storage, dir)
	for _, p := range []string{b.guestDir, storage, config.Host.ManagementDirectory, filepath.Join(config.Host.ManagementDirectory, "uploads")} {
		if err = process.EnsurePrivateDir(p); err != nil {
			t.Fatal(err)
		}
	}
	config.Modules = []runtime.ModuleSpec{{ModuleID: "fixture", ImageDigest: b.digest, Entrypoint: []string{"/fixture"}, UID: 1001, GID: 1001,
		Config: &wire.JSONValue{Json: []byte(portableConfigFixture)}, Approval: &wire.Grants{
			EgressPolicy: wire.EgressPolicy_EGRESS_POLICY_NONE, ResourceClass: wire.ResourceClass_RESOURCE_CLASS_GENERAL,
			ResourceLimits:   &wire.ResourceLimits{CpuMillicores: 500, MemoryBytes: 256 << 20, MaxPids: 64, PersistentBytes: 1 << 30, ScratchBytes: 256 << 20},
			CoreCapabilities: []*wire.CapabilityGrant{{Name: core.CapabilityConfigRead, ResourceScopes: portableScope()}},
		}}}
	raw, err := runtime.EncodePortableConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := process.Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- session.Serve(ctx, listener, creds, b) }()
	defer func() {
		cancel()
		if err := <-serverDone; err != nil {
			t.Error(err)
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.child != nil {
			_ = b.child.Kill()
		}
	}()
	in, toWorker := io.Pipe()
	fromWorker, out := io.Pipe()
	defer toWorker.Close()
	defer fromWorker.Close()
	workerDone := make(chan error, 1)
	go func() {
		err := RunWorker(ctx, in, out, io.Discard, session.WorkerArg)
		_ = out.Close()
		workerDone <- err
	}()
	if err = session.WriteWorkerInit(toWorker, session.WorkerInit{Endpoint: endpoint, Credentials: creds, Config: raw}); err != nil {
		t.Fatal(err)
	}
	ready, err := session.ReadWorkerEvent(fromWorker)
	if err != nil || ready.Type != "READY" || len(ready.Modules) != 1 || ready.Modules[0].State != string(runtime.Running) || ready.Modules[0].InstanceID == "" {
		t.Fatalf("worker did not observe real RUNNING: %+v (%v)", ready, err)
	}
	if err = session.WriteWorkerDrain(toWorker, time.Now().Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	terminal, err := session.ReadWorkerEvent(fromWorker)
	if err != nil || terminal.Type != "DRAINED" || !terminal.Clean || len(terminal.Modules) != 1 || terminal.Modules[0].InstanceID != ready.Modules[0].InstanceID || !terminal.Modules[0].CleanupComplete {
		t.Fatalf("worker did not positively report cleanup: %+v (%v)", terminal, err)
	}
	if err = <-workerDone; err != nil {
		t.Fatal(err)
	}
	stages, err := os.ReadFile(b.trace)
	if err != nil || string(stages) != "manifest\negress\ninit\nstart\ndrain\nstop\nrelease\n" {
		t.Fatalf("unexpected authenticated lifecycle order: %q (%v)", stages, err)
	}
}
