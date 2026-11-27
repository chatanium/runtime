//go:build linux

package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/gvxipc"
	"github.com/thirdscam/chatanium/internal/gvxstage"
	"github.com/thirdscam/chatanium/internal/provision"
	"golang.org/x/sys/unix"
)

type GvxPlatformConfig struct {
	Owner                                                  UnitIdentity
	Bundle                                                 bundle.Verified
	Sandbox                                                NumericIdentity
	StartupDeadline, OperationTimeout, TerminationDeadline time.Duration
}
type GvxPlatform struct {
	cfg       GvxPlatformConfig
	store     *Store
	systemd   *Systemd
	storage   *Storage
	network   *Network
	images    *ImageManager
	mu        sync.Mutex
	instances map[string]*gvxInstance
	journal   CreateJournal
	closed    bool
}
type gvxInstance struct {
	mu                 sync.Mutex
	lease              Lease
	service            OwnedService
	gate               *stageGate
	pin                *os.File
	unit               UnitIdentity
	terminal, recorded chan struct{}
	terminalErr        error
	exit               ProcessExit
	started            bool
}

func NewGvxPlatform(c GvxPlatformConfig, s *Store, d *Systemd, storage *Storage, network *Network, images *ImageManager) (*GvxPlatform, error) {
	if s == nil || d == nil || storage == nil || network == nil || images == nil || c.Owner.Name == "" || c.Sandbox.UID == 0 || c.Sandbox.GID == 0 || c.StartupDeadline <= 0 || c.OperationTimeout <= 0 || c.TerminationDeadline <= 0 {
		return nil, invalid("complete finite gvx platform configuration required")
	}
	if c.Bundle.Digest != d.bundle.Digest {
		return nil, invalid("systemd and platform bundle differ")
	}
	if e := d.BindStore(s); e != nil {
		return nil, e
	}
	return &GvxPlatform{cfg: c, store: s, systemd: d, storage: storage, network: network, images: images, instances: map[string]*gvxInstance{}}, nil
}
func (p *GvxPlatform) BindCreateJournal(j CreateJournal) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if j != p.store || p.journal != nil && p.journal != j {
		return errors.New("platform requires the same live installation store")
	}
	p.journal = j
	return nil
}
func (p *GvxPlatform) Preflight(ctx context.Context) error {
	if p.systemd.admissionClosed.Load() {
		return prerequisite(errors.New("systemd admission is closed"))
	}
	if e := p.systemd.connected(); e != nil {
		return prerequisite(e)
	}
	if _, e := p.systemd.Observe(ctx, p.cfg.Owner); e != nil {
		return prerequisite(e)
	}
	_, e := bundle.VerifyDirectory(ctx, p.cfg.Bundle.Root, p.cfg.Bundle.Manifest)
	return e
}
func (p *GvxPlatform) ImageManifest(ctx context.Context, selector string, max int64) ([]byte, error) {
	return p.images.ImageManifest(ctx, selector, max)
}
func serviceName(o Ownership, generation string) string {
	raw := provision.DomainDigest("chatanium-unit-v1", []byte(o.RuntimeInstallationID+"\x00"+o.InstallationID+"\x00"+o.EpochID+"\x00"+o.InstanceID+"\x00"+generation))
	return "chatanium-gvx-" + strings.TrimPrefix(raw, "sha256:") + "-" + generation + ".service"
}
func (p *GvxPlatform) Create(ctx context.Context, spec LaunchSpec, l Lease, bootstrap []string) (process *StageProcess, err error) {
	p.mu.Lock()
	if p.closed || p.journal == nil {
		p.mu.Unlock()
		return nil, errors.New("platform admission closed or journal unbound")
	}
	if p.instances[l.Ownership.InstanceID] != nil {
		p.mu.Unlock()
		return nil, ErrCreateAlreadySubmitted
	}
	i := &gvxInstance{lease: l, terminal: make(chan struct{})}
	p.instances[l.Ownership.InstanceID] = i
	p.mu.Unlock()
	if p.systemd.admissionClosed.Load() {
		return nil, errors.New("systemd admission is closed")
	}
	if e := gvxipc.Workspace(gvxipc.Limits{ControlMessageMaxBytes: spec.Resources.ControlMessageMaxBytes, LogBufferBytes: spec.Resources.LogBufferBytes}); e != nil {
		return nil, e
	}
	if l.Spec.InstanceID != spec.InstanceID || l.Ownership.InstanceID != spec.InstanceID || l.Ownership.Unit.Name != "" || l.SandboxUID != p.cfg.Sandbox.UID || l.SandboxGID != p.cfg.Sandbox.GID {
		return nil, invalid("launch differs from current owned lease")
	}
	remaining, e := remainingStartup(l)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	supplied, encodeErr := json.Marshal(spec)
	if encodeErr != nil {
		return nil, encodeErr
	}
	allocated, encodeErr := json.Marshal(l.Spec)
	if encodeErr != nil {
		return nil, encodeErr
	}
	if string(supplied) != string(allocated) {
		return nil, errors.New("launch specification differs from allocated lease")
	}
	current, _, e := p.store.lease(ctx, l.Ownership.EpochID, l.Ownership.InstanceID)
	if e != nil {
		return nil, e
	}
	if current.Ownership != l.Ownership || current.ImageRecordID != l.ImageRecordID || current.CacheGenerationID != l.CacheGenerationID {
		return nil, errors.New("lease changed before create")
	}
	record, e := p.store.Image(ctx, l.ImageRecordID)
	if e != nil {
		return nil, e
	}
	if record.ID != l.ImageRecordID {
		return nil, errors.New("image record binding mismatch")
	}
	if e = p.storage.Prepare(ctx, l); e != nil {
		return nil, e
	}
	roots, e := p.storage.PrepareRoots(ctx, l)
	if e != nil {
		return nil, e
	}
	view, e := p.images.InstanceView(ctx, l)
	if e != nil {
		return nil, e
	}
	network, e := p.network.Prepare(ctx, l)
	if e != nil {
		return nil, e
	}
	if e = p.network.VerifyClosed(ctx, l.Ownership); e != nil {
		return nil, e
	}
	endpoint, listener, pin, e := p.storage.CreateEndpoint(ctx, l)
	if e != nil {
		return nil, e
	}
	defer func() {
		if err != nil {
			listener.Close()
			pin.Close()
		}
	}()
	dup, e := unix.FcntlInt(pin.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	i.pin = os.NewFile(uintptr(dup), "root-endpoint-pin")
	init, e := composeBridgeInit(spec, record, bootstrap, roots)
	if e != nil {
		return nil, e
	}
	control := int(spec.Resources.ControlMessageMaxBytes)
	if control > 60<<10 {
		control = 60 << 10
	}
	if _, e = gvxipc.ValidateInit(init, control); e != nil {
		return nil, e
	}
	generation, e := randomGeneration()
	if e != nil {
		return nil, e
	}
	generation = strings.ReplaceAll(p.systemd.boot, "-", "") + "-" + generation
	manifest, e := p.store.Installation(ctx)
	if e != nil {
		return nil, e
	}
	cwd := filepath.Join(filepath.Dir(l.ScratchPath), "work")
	tmp := filepath.Join(filepath.Dir(l.ScratchPath), "tmp")
	rungv, _, _, rungvDigest, e := p.systemd.program(bundle.Rungv)
	if e != nil {
		return nil, e
	}
	rungvPath := filepath.Join(p.cfg.Bundle.Root, rungv.Path)
	bridge, e := p.cfg.Bundle.Program(bundle.GuestBridge)
	if e != nil {
		return nil, e
	}
	projectedLease := l
	projectedLease.PersistentPath = "/chatanium/data"
	projectedLease.ScratchPath = "/chatanium/scratch"
	argv, e := runArguments(rungvPath, record, "/chatanium/cache", projectedLease, "/chatanium/tmp", "/chatanium/scratch", "/chatanium/bootstrap", remaining, p.network.cfg.Resolvers)
	if e != nil {
		return nil, e
	}
	config := gvxstage.Config{Version: 1, RuntimeInstallationID: l.Ownership.RuntimeInstallationID, EpochID: l.Ownership.EpochID, InstanceID: l.Ownership.InstanceID, Generation: generation, RungvPath: rungvPath, RungvDigest: rungvDigest, Workdir: "/chatanium/work", Argv: argv, Env: stageEnvironment("/chatanium/tmp"), DeadlineBootNS: l.StartupDeadlineBootNS}
	config.GatePath = filepath.Join(manifest.Paths.RunRoot, "stages", generation, "gate.sock")
	gate, configPath, e := createStageGate(manifest.Paths.RunRoot, config, l.SandboxGID)
	if e != nil {
		return nil, e
	}
	i.gate = gate
	root := filepath.Join(filepath.Dir(l.ScratchPath), "stage-root")
	if e = os.Mkdir(root, 0755); e != nil {
		return nil, e
	}
	mounts := []OwnedMount{{Source: p.cfg.Bundle.Root, Target: p.cfg.Bundle.Root, ReadOnly: true}, {Source: view, Target: "/chatanium/cache", ReadOnly: true}, {Source: l.PersistentPath, Target: "/chatanium/data"}, {Source: l.ScratchPath, Target: "/chatanium/scratch"}, {Source: tmp, Target: "/chatanium/tmp"}, {Source: tmp, Target: "/tmp"}, {Source: cwd, Target: "/chatanium/work"}, {Source: filepath.Join(p.cfg.Bundle.Root, bridge.Path), Target: "/chatanium/bootstrap/guest-bridge", ReadOnly: true}, {Source: gate.directory, Target: gate.directory, ReadOnly: true}}
	service := OwnedService{Owner: p.cfg.Owner, Ownership: l.Ownership, Name: serviceName(l.Ownership, generation), Generation: generation, Program: bundle.Stage, Argv: []string{"gvx-stage", configPath}, Env: stageEnvironment("/chatanium/tmp"), Identity: p.cfg.Sandbox, Limits: spec.Resources, WorkingDirectory: "/chatanium/work", NetworkNamespacePath: network.NetnsPath, RootDirectory: root, Mounts: mounts, TimeoutStop: p.cfg.TerminationDeadline}
	i.service = service
	projected := UnitIdentity{Name: service.Name, Generation: generation, InvocationID: strings.Repeat("f", 32), BootID: p.systemd.boot, CgroupPath: "/" + strings.Repeat("c", 4095), MainPID: mathMaxPID, StartTime: ^uint64(0), ExecutableDigest: "sha256:" + strings.Repeat("f", 64), ResourceFingerprint: resourceFingerprint(spec.Resources)}
	if e = ValidateCreateResponse(&StageProcess{Unit: projected, Init: init, EndpointIdentity: endpoint}, int(spec.Resources.ControlMessageMaxBytes)); e != nil {
		return nil, e
	}
	input, stdin, e := os.Pipe()
	if e != nil {
		return nil, e
	}
	stdout, out, e := os.Pipe()
	if e != nil {
		input.Close()
		stdin.Close()
		return nil, e
	}
	stderr, diag, e := os.Pipe()
	if e != nil {
		input.Close()
		stdin.Close()
		stdout.Close()
		out.Close()
		return nil, e
	}
	defer input.Close()
	defer out.Close()
	defer diag.Close()
	defer func() {
		if err != nil {
			stdin.Close()
			stdout.Close()
			stderr.Close()
		}
	}()
	if e = p.journal.SubmitCreate(ctx, l.Ownership, CreateService, service.Name); e != nil {
		return nil, e
	}
	observation, e := p.systemd.StartOwned(ctx, service, StandardFiles{input, out, diag})
	if e != nil {
		if rejection := systemdRejection(e); rejection != "" {
			return nil, errors.Join(e, p.journal.RejectCreate(ctx, l.Ownership, CreateService, service.Name, rejection))
		}
		return nil, errors.Join(ErrCreateUnresolved, e)
	}
	i.unit = observation.Unit
	if observation.Exit != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), p.cfg.OperationTimeout)
		defer cancel()
		rejectErr := p.journal.RejectCreate(cleanup, l.Ownership, CreateService, service.Name, "stage-terminal-before-ready")
		releaseErr := p.systemd.ReleaseReference(cleanup, i.unit)
		return nil, classifiedFailure(FailureNotRunning, errors.Join(rejectErr, releaseErr))
	}
	i.recorded = make(chan struct{})
	go p.observeTerminal(i)
	defer func() {
		if err != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), p.cfg.OperationTimeout)
			_ = p.store.RecordFailure(cleanup, l.Ownership, PhasePrestart, FailureIsolation)
			_ = p.store.RecordUnit(cleanup, l.Ownership, observation)
			i.lease.Ownership.Unit = i.unit
			_ = gate.close()
			cancel()
		}
		close(i.recorded)
	}()
	if e = gate.authenticate(ctx, p.systemd, i.unit, service); e != nil {
		return nil, e
	}
	if e = p.storage.Verify(ctx, l); e != nil {
		return nil, e
	}
	if e = p.network.VerifyClosed(ctx, l.Ownership); e != nil {
		return nil, e
	}
	if e = p.store.RecordUnit(ctx, l.Ownership, observation); e != nil {
		return nil, e
	}
	i.lease.Ownership.Unit = i.unit
	return &StageProcess{Unit: i.unit, Init: init, EndpointIdentity: endpoint, Stdin: stdin, Stdout: stdout, Stderr: stderr, Listener: listener, Endpoint: pin}, nil
}

const mathMaxPID = int(^uint32(0) >> 1)

func composeBridgeInit(s LaunchSpec, r provision.ImageRecord, bootstrap []string, roots gvxcontract.RootInitManifest) (gvxcontract.BridgeInit, error) {
	argv := append([]string{}, s.Entrypoint...)
	if len(argv) == 0 {
		argv = append(argv, r.Entrypoint...)
	}
	if len(s.Args) > 0 {
		argv = append(argv, s.Args...)
	} else {
		argv = append(argv, r.Cmd...)
	}
	env := append([]string{}, r.ImageEnv...)
	seen := map[string]bool{}
	for _, entry := range env {
		k, _, ok := strings.Cut(entry, "=")
		if !ok || seen[k] || strings.HasPrefix(k, "PLUGIN_") || k == "FLEXMODULE_PLUGIN" || strings.HasPrefix(k, "CHATANIUM_GVX_") {
			return gvxcontract.BridgeInit{}, errors.New("image environment collides with trusted bootstrap")
		}
		seen[k] = true
	}
	socket := ""
	for _, entry := range bootstrap {
		k, v, ok := strings.Cut(entry, "=")
		if !ok || seen[k] {
			return gvxcontract.BridgeInit{}, errors.New("duplicate bootstrap environment")
		}
		switch k {
		case "FLEXMODULE_PLUGIN", "PLUGIN_PROTOCOL_VERSIONS", "PLUGIN_MULTIPLEX_GRPC", "PLUGIN_CLIENT_CERT", "PLUGIN_UNIX_SOCKET_DIR", "PLUGIN_UNIX_SOCKET_GROUP", "PLUGIN_MIN_PORT", "PLUGIN_MAX_PORT":
		default:
			return gvxcontract.BridgeInit{}, errors.New("unapproved bootstrap environment")
		}
		if k == "PLUGIN_UNIX_SOCKET_DIR" {
			socket = v
		}
		seen[k] = true
		env = append(env, entry)
	}
	workdir := r.Workdir
	if workdir == "" {
		workdir = "/"
	}
	return gvxcontract.BridgeInit{Argv: argv, Env: env, Workdir: workdir, UID: s.UID, GID: s.GID, SocketDir: socket, Roots: roots}, nil
}
func runArguments(path string, r provision.ImageRecord, view string, l Lease, tmp, work, bridge string, budget time.Duration, resolvers []string) ([]string, error) {
	args := []string{path, "run", "--platform=systrap", "--arch=amd64", "--lockdown=true", "--privileged=false", "--net-raw=false", "--allow-packet-socket-write=false", "--allow-suid=false", "--read-only=true", "--user=0:0", "--workdir=/", "--cache-dir=" + view, "--registry-url=https://chatanium.invalid", "--pull=never", "--entrypoint=/run/chatanium-bootstrap/guest-bridge"}
	for _, mount := range []struct {
		src, dst string
		ro       bool
	}{{l.PersistentPath, DataMountpoint, false}, {work, ScratchMountpoint, false}, {tmp, "/tmp", false}, {bridge, "/run/chatanium-bootstrap", true}} {
		if strings.ContainsAny(mount.src, ",:\x00") {
			return nil, errors.New("unrepresentable mount path")
		}
		arg := "--mount=type=bind,src=" + mount.src + ",dst=" + mount.dst + ",driver=hostfs"
		if mount.ro {
			arg += ",readonly"
		}
		args = append(args, arg)
	}
	seen := map[string]bool{}
	for _, entry := range r.ImageEnv {
		k, _, ok := strings.Cut(entry, "=")
		if !ok || seen[k] || k == "" || strings.ContainsRune(entry, 0) {
			return nil, errors.New("invalid image environment")
		}
		seen[k] = true
		args = append(args, "--env="+k+"=")
	}
	for _, entry := range []string{"PATH=/usr/bin:/bin", "HOME=/tmp", "TMPDIR=/tmp", "LANG=C", "LC_ALL=C", "CHATANIUM_GVX_STARTUP_TIMEOUT_NS=" + strconv.FormatInt(int64(budget), 10), "CHATANIUM_GVX_CONTROL_MAX_BYTES=" + strconv.FormatInt(l.Spec.Resources.ControlMessageMaxBytes, 10), "CHATANIUM_GVX_LOG_BUFFER_BYTES=" + strconv.FormatInt(l.Spec.Resources.LogBufferBytes, 10)} {
		args = append(args, "--env="+entry)
	}
	if l.Topology == NetworkNone {
		args = append(args, "--net=none")
	} else {
		args = append(args, "--net=nat")
	}
	for _, resolver := range resolvers {
		args = append(args, "--host-dns="+resolver)
	}
	args = append(args, r.ExecutionRef, "--stdio-v1")
	return args, nil
}
func (p *GvxPlatform) owned(ctx context.Context, o Ownership) (Lease, *gvxInstance, error) {
	l, _, e := p.store.lease(ctx, o.EpochID, o.InstanceID)
	if e != nil {
		return l, nil, e
	}
	if l.Ownership.RuntimeInstallationID != o.RuntimeInstallationID || l.Ownership.InstallationID != o.InstallationID || o.Unit.Name != "" && o.Unit != l.Ownership.Unit {
		return l, nil, errors.New("platform ownership mismatch")
	}
	p.mu.Lock()
	i := p.instances[o.InstanceID]
	p.mu.Unlock()
	return l, i, nil
}
func (p *GvxPlatform) Start(ctx context.Context, o Ownership) error {
	l, i, e := p.owned(ctx, o)
	if e != nil {
		return e
	}
	if i == nil || l.Ownership.Unit != i.unit {
		return errors.New("old epoch or lost stage cannot be adopted")
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.started {
		return errors.New("stage Start is one-shot")
	}
	if _, e = remainingStartup(l); e != nil {
		return e
	}
	if e = p.storage.Verify(ctx, l); e != nil {
		return e
	}
	if e = p.network.VerifyClosed(ctx, l.Ownership); e != nil {
		return e
	}
	if p.systemd.admissionClosed.Load() {
		return errors.New("systemd admission is closed")
	}
	if _, e = p.systemd.Observe(ctx, i.unit); e != nil {
		return e
	}
	if e = verifyServiceProcess(i.unit, i.service, p.systemd); e != nil {
		return e
	}
	if e = p.store.state(ctx, o.InstanceID, "STARTING", ""); e != nil {
		return e
	}
	if e = i.gate.start(); e != nil {
		return e
	}
	i.started = true
	return nil
}
func (p *GvxPlatform) ConfirmGuestStorage(ctx context.Context, o Ownership, result gvxcontract.RootInitResult) error {
	l, _, e := p.owned(ctx, o)
	if e != nil {
		return e
	}
	return p.storage.ConfirmRoots(ctx, l, result)
}
func (p *GvxPlatform) observeTerminal(i *gvxInstance) {
	defer close(i.terminal)
	exit, e := p.systemd.Wait(context.Background(), i.unit)
	if i.gate != nil {
		_ = i.gate.close()
	}
	<-i.recorded
	first := e
	cleanup, cancel := context.WithTimeout(context.Background(), p.cfg.OperationTimeout+p.cfg.TerminationDeadline)
	defer cancel()
	if e != nil {
		_ = p.store.RecordFailure(cleanup, i.lease.Ownership, PhaseCleanup, FailureInspect)
		revocationCtx, revokeDone := context.WithTimeout(cleanup, p.cfg.OperationTimeout)
		revocation := p.network.SetEgress(revocationCtx, i.lease.Ownership, EgressNone)
		revokeDone()
		v, readErr := p.store.Unit(cleanup, i.lease.Ownership)
		if readErr == nil {
			readErr = p.systemd.retainObserved(cleanup, i.lease.Ownership, v)
		}
		if readErr == nil {
			readErr = p.systemd.Stop(cleanup, i.unit)
		}
		if readErr == nil {
			exit, readErr = p.systemd.waitNative(cleanup, i.unit)
		}
		first = errors.Join(first, revocation)
		e = readErr
	}
	if e == nil {
		owner := i.lease.Ownership
		owner.Unit = UnitIdentity{}
		e = p.systemd.recordStageTerminal(cleanup, owner, i.unit, exit)
		if e == nil {
			e = p.systemd.ReleaseReference(cleanup, i.unit)
		}
	}
	i.mu.Lock()
	i.exit = exit
	i.terminalErr = errors.Join(first, e)
	i.mu.Unlock()
}
func (p *GvxPlatform) Wait(ctx context.Context, o Ownership) (ProcessExit, error) {
	l, i, e := p.owned(ctx, o)
	if e != nil {
		return ProcessExit{}, e
	}
	if i != nil {
		select {
		case <-i.terminal:
			i.mu.Lock()
			defer i.mu.Unlock()
			return i.exit, i.terminalErr
		case <-ctx.Done():
			return ProcessExit{}, ctx.Err()
		}
	}
	v, e := p.store.Unit(ctx, l.Ownership)
	if e != nil {
		return ProcessExit{}, e
	}
	if v.Exit == nil {
		return ProcessExit{}, errors.New("UNKNOWN terminal result; recovery must reconcile")
	}
	return *v.Exit, nil
}
func (p *GvxPlatform) SetEgress(ctx context.Context, o Ownership, policy EgressPolicy) error {
	l, _, e := p.owned(ctx, o)
	if e != nil {
		return e
	}
	if policy != EgressNone {
		if e = p.systemd.connected(); e != nil {
			return e
		}
		if p.systemd.admissionClosed.Load() {
			return errors.New("systemd admission is closed")
		}
	}
	return p.network.SetEgress(ctx, l.Ownership, policy)
}
func (p *GvxPlatform) Terminate(ctx context.Context, o Ownership) error {
	cleanup, cancel := context.WithTimeout(context.Background(), p.cfg.OperationTimeout+p.cfg.TerminationDeadline)
	defer cancel()
	ctx = cleanup
	l, i, e := p.owned(ctx, o)
	if e != nil {
		return e
	}
	revokeCtx, revokeDone := context.WithTimeout(ctx, p.cfg.OperationTimeout)
	revocation := p.network.SetEgress(revokeCtx, l.Ownership, EgressNone)
	revokeDone()
	u := l.Ownership.Unit
	if u.Name == "" {
		e = p.resolveSubmission(ctx, l)
		if e != nil {
			return errors.Join(revocation, e)
		}
		l, _, e = p.store.lease(ctx, o.EpochID, o.InstanceID)
		if e != nil {
			return errors.Join(revocation, e)
		}
		u = l.Ownership.Unit
		if u.Name == "" {
			return revocation
		}
	}
	if i != nil && i.gate != nil {
		_ = i.gate.close()
	}
	v, e := p.store.Unit(ctx, l.Ownership)
	if e != nil {
		return errors.Join(revocation, e)
	}
	if e = p.systemd.retainObserved(ctx, l.Ownership, v); e != nil {
		return errors.Join(revocation, e)
	}
	if u.BootID != p.systemd.boot {
		if _, e = p.systemd.StorageCleanupBarrier(ctx, l.Ownership); e != nil {
			return errors.Join(revocation, e)
		}
	} else {
		if v.Exit == nil && v.Absence == nil {
			if e = p.systemd.Stop(ctx, u); e != nil {
				return errors.Join(revocation, e)
			}
			if i != nil && i.recorded != nil {
				select {
				case <-i.terminal:
				case <-ctx.Done():
					return errors.Join(revocation, ctx.Err())
				}
			}
			v, e = p.store.Unit(ctx, l.Ownership)
			if e != nil {
				return errors.Join(revocation, e)
			}
			if v.Exit == nil && v.Absence == nil {
				exit, waitErr := p.systemd.waitNative(ctx, u)
				if waitErr != nil {
					return errors.Join(revocation, waitErr)
				}
				if e = p.systemd.recordStageTerminal(ctx, l.Ownership, u, exit); e != nil {
					return errors.Join(revocation, e)
				}
			}
		}
		if v.Absence == nil {
			if e = p.systemd.ReleaseReference(ctx, u); e != nil {
				return errors.Join(revocation, e)
			}
		}
	}
	_, e = p.systemd.Settle(ctx, u)
	return errors.Join(revocation, e)
}
func (p *GvxPlatform) resolveSubmission(ctx context.Context, l Lease) error {
	r, ok, e := p.store.LookupCreate(ctx, l.Ownership, CreateService)
	if e != nil || !ok {
		return e
	}
	if r.State == CreateRejected {
		return p.systemd.settleSubmission(ctx, r.Identity)
	}
	name := strings.TrimSuffix(r.Identity, ".service")
	prefix := "chatanium-gvx-"
	if !strings.HasPrefix(name, prefix) || len(name) < len(prefix)+64+1+65 {
		return ErrCreateUnresolved
	}
	generation := name[len(prefix)+65:]
	if serviceName(l.Ownership, generation) != r.Identity || len(generation) != 65 || generation[32] != '-' {
		return errors.New("submitted service identity binding mismatch")
	}
	if generation[:32] != strings.ReplaceAll(p.systemd.boot, "-", "") {
		if e = p.systemd.proveUnitAbsent(ctx, r.Identity); e != nil {
			return e
		}
		return p.store.RejectCreate(ctx, l.Ownership, CreateService, r.Identity, "boot-fenced:"+generation[:32]+":"+strings.ReplaceAll(p.systemd.boot, "-", ""))
	}
	observation, e := p.systemd.RecoverOwnedUnit(ctx, r.Identity, generation, bundle.Stage, l.Spec.Resources)
	if e != nil {
		return errors.Join(ErrCreateUnresolved, e)
	}
	if observation.Exit != nil {
		if e = p.store.RejectCreate(ctx, l.Ownership, CreateService, r.Identity, "stage-terminal-before-ready"); e != nil {
			return e
		}
		if e = p.systemd.ReleaseReference(ctx, observation.Unit); e != nil {
			return e
		}
		return p.systemd.settleSubmission(ctx, r.Identity)
	}
	if e = p.store.RecordFailure(ctx, l.Ownership, PhaseCleanup, FailureStartAPI); e != nil {
		return e
	}
	if e = p.store.RecordUnit(ctx, l.Ownership, observation); e != nil {
		return e
	}
	p.systemd.mu.Lock()
	if ref := p.systemd.refs[r.Identity]; ref != nil {
		ref.service.Ownership = l.Ownership
	}
	p.systemd.mu.Unlock()
	return nil
}
func (p *GvxPlatform) Reconcile(ctx context.Context, o Ownership) error {
	cleanup, cancel := context.WithTimeout(context.Background(), 3*p.cfg.OperationTimeout+p.cfg.TerminationDeadline)
	defer cancel()
	ctx = cleanup
	l, i, e := p.owned(ctx, o)
	if e != nil {
		return e
	}
	termination := p.Terminate(ctx, l.Ownership)
	if termination != nil {
		if recordErr := p.store.RecordFailure(ctx, l.Ownership, PhaseCleanup, failureReason(termination, FailureInspect)); recordErr != nil {
			return errors.Join(termination, recordErr)
		}
	}
	l, _, e = p.store.lease(ctx, o.EpochID, o.InstanceID)
	if e != nil {
		return errors.Join(termination, e)
	}
	if i != nil {
		i.mu.Lock()
		if i.gate != nil {
			e = i.gate.close()
		}
		if i.pin != nil {
			e = errors.Join(e, i.pin.Close())
			i.pin = nil
		}
		i.mu.Unlock()
		if e != nil {
			return errors.Join(termination, e)
		}
	}
	// Cleanup still escalates after a failed revoke, but never crosses an
	// unproven terminal/reference barrier.
	evidence, e := p.systemd.StorageCleanupBarrier(ctx, l.Ownership)
	if e != nil {
		return errors.Join(termination, e)
	}
	if e = p.network.Reconcile(ctx, l.Ownership); e != nil {
		return errors.Join(termination, e)
	}
	if e = p.images.Release(ctx, l, evidence); e != nil {
		return errors.Join(termination, e)
	}
	if e = p.storage.Cleanup(ctx, l); e != nil {
		return errors.Join(termination, e)
	}
	directory := ""
	unitName := l.Ownership.Unit.Name
	if i != nil && i.gate != nil {
		directory = i.gate.directory
		unitName = i.service.Name
	} else {
		manifest, readErr := p.store.Installation(ctx)
		if readErr != nil {
			return readErr
		}
		submission, found, readErr := p.store.LookupCreate(ctx, l.Ownership, CreateService)
		if readErr != nil {
			return readErr
		}
		if found {
			unitName = submission.Identity
			prefix := "chatanium-gvx-"
			name := strings.TrimSuffix(submission.Identity, ".service")
			if strings.HasPrefix(name, prefix) && len(name) == len(prefix)+64+1+65 {
				generation := name[len(prefix)+65:]
				if safeID(generation) && serviceName(l.Ownership, generation) == submission.Identity {
					directory = filepath.Join(manifest.Paths.RunRoot, "stages", generation)
				}
			}
		}
	}
	if directory != "" {
		if e = os.RemoveAll(directory); e != nil {
			return e
		}
	}
	p.systemd.mu.Lock()
	if ref := p.systemd.refs[unitName]; ref != nil && ref.recorded && ref.released {
		delete(p.systemd.refs, unitName)
		delete(p.systemd.jobs, ref.job)
	}
	p.systemd.mu.Unlock()
	p.mu.Lock()
	delete(p.instances, o.InstanceID)
	p.mu.Unlock()
	return nil
}
func (p *GvxPlatform) Close() error {
	p.mu.Lock()
	p.closed = true
	owners := make([]Ownership, 0, len(p.instances))
	for _, i := range p.instances {
		owners = append(owners, i.lease.Ownership)
	}
	p.mu.Unlock()
	var failures []error
	for _, owner := range owners {
		ctx, cancel := context.WithTimeout(context.Background(), p.cfg.OperationTimeout+p.cfg.TerminationDeadline)
		failures = append(failures, p.Reconcile(ctx, owner))
		cancel()
	}
	return errors.Join(failures...)
}
