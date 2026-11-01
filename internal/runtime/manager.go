package runtime

import (
	"context"
	"errors"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	"github.com/thirdscam/chatanium/internal/host"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type Manager struct {
	mu          sync.Mutex
	reconcileMu sync.Mutex
	config      Config
	options     ManagerOptions
	instances   map[ModuleID]*Instance
	installed   map[ModuleID]struct{}
	backends    map[string]BackendRegistration
	operations  map[string]OperationPolicy
	events      map[string]EventPolicy
	credentials *CredentialRegistry
	dispatcher  *Dispatcher
}

func NewManager(config Config, options ManagerOptions) (*Manager, error) {
	profiles := make(map[string]ResourceProfile, len(config.ResourceProfiles))
	for name, p := range config.ResourceProfiles {
		profiles[name] = p
	}
	config.ResourceProfiles = profiles
	options.Backends = append([]BackendRegistration(nil), options.Backends...)
	config.applyDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if options.Host == nil || options.FileTransfer == nil || options.FileCleanup == nil {
		return nil, invalidConfig()
	}
	m := &Manager{config: config, options: options, instances: make(map[ModuleID]*Instance), installed: make(map[ModuleID]struct{}), backends: make(map[string]BackendRegistration), operations: make(map[string]OperationPolicy), events: make(map[string]EventPolicy)}
	for _, s := range config.Modules {
		m.installed[s.ModuleID] = struct{}{}
	}
	for _, p := range []OperationPolicy{{Operation: "GetConfig", Capability: core.CapabilityConfigRead, InitSafe: true, ResourceFree: true, Class: FiniteOperation}, {Operation: "Upload", Capability: core.CapabilityUpload, ResourceFree: true, Class: LongLivedOperation}, {Operation: "DeleteUpload", Capability: core.CapabilityUpload, InitSafe: true, ResourceFree: true, Class: OwnerCleanupOperation}} {
		m.operations[operationKey(p.Backend, p.Operation)] = p
	}
	for _, b := range options.Backends {
		configured, ok := config.Backends[b.ID]
		if !ok || configured.Major != b.Major || b.ID == "" || b.Major == 0 || b.Adapter == nil || b.Register == nil || b.ValidateSelector == nil {
			return nil, invalidConfig()
		}
		if _, exists := m.backends[b.ID]; exists {
			return nil, invalidConfig()
		}
		b.Operations = append([]OperationPolicy(nil), b.Operations...)
		for _, p := range b.Operations {
			if p.Backend != b.ID || p.Operation == "" || p.Capability == "" || p.Class < FiniteOperation || p.Class > OwnerCleanupOperation || p.DrainSafe && p.Class != FiniteOperation {
				return nil, invalidConfig()
			}
			key := operationKey(p.Backend, p.Operation)
			if _, exists := m.operations[key]; exists {
				return nil, invalidConfig()
			}
			m.operations[key] = p
		}
		b.Events = append([]EventPolicy(nil), b.Events...)
		for _, event := range b.Events {
			key := operationKey(b.ID, event.EventType)
			if event.EventType == "" || event.Operation == "" || event.PayloadTypeURL == "" {
				return nil, invalidConfig()
			}
			if _, ok := m.operations[operationKey(b.ID, event.Operation)]; !ok {
				return nil, invalidConfig()
			}
			if _, exists := m.events[key]; exists {
				return nil, invalidConfig()
			}
			m.events[key] = event
		}
		m.backends[b.ID] = b
	}
	for id := range config.Backends {
		if _, ok := m.backends[id]; !ok {
			return nil, invalidConfig()
		}
	}
	for _, s := range config.Modules {
		for _, g := range s.Approval.Backends {
			b, ok := m.backends[g.BackendId]
			if !ok || b.Major != g.ProtocolMajor || b.validateGrant(g) != nil {
				return nil, invalidConfig()
			}
		}
	}
	// Backend-private configuration belongs to the composed adapter, not the
	// generic manager. Retain only protocol metadata needed for future launches.
	metadata := make(map[string]BackendConfig, len(config.Backends))
	for id, b := range config.Backends {
		metadata[id] = BackendConfig{Major: b.Major}
	}
	m.config.Backends = metadata
	m.config.Modules = nil
	m.credentials = &CredentialRegistry{manager: m}
	m.dispatcher = &Dispatcher{manager: m}
	return m, nil
}
func (m *Manager) Credentials() *CredentialRegistry { return m.credentials }
func (m *Manager) Dispatcher() *Dispatcher          { return m.dispatcher }
func (m *Manager) Instance(id ModuleID) (*Instance, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i, ok := m.instances[id]
	return i, ok
}
func (m *Manager) Launch(ctx context.Context, spec ModuleSpec) (result *Instance, launchErr error) {
	if ctx == nil {
		return nil, invalidConfig()
	}
	if err := m.config.validateSpec(spec); err != nil {
		return nil, err
	}
	spec = cloneSpec(spec)
	for _, grant := range spec.Approval.Backends {
		registration, ok := m.backends[grant.BackendId]
		if !ok || registration.Major != grant.ProtocolMajor || registration.validateGrant(grant) != nil {
			return nil, invalidConfig()
		}
	}
	for _, binding := range spec.CredentialBindings {
		registration, ok := m.backends[binding.BackendID]
		if !ok || registration.ValidateSelector(binding.Resource) != nil {
			return nil, invalidConfig()
		}
	}
	m.mu.Lock()
	if _, ok := m.installed[spec.ModuleID]; !ok {
		m.mu.Unlock()
		return nil, ErrModuleNotInstalled
	}
	if old := m.instances[spec.ModuleID]; old != nil {
		old.mu.Lock()
		busy := !old.cleanupComplete
		old.mu.Unlock()
		if busy {
			m.mu.Unlock()
			return nil, ErrModuleAlreadyActive
		}
	}
	id, err := randomID()
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	startup, cancelStartup := context.WithTimeout(ctx, time.Duration(m.config.Defaults.StartupDeadline))
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	i := &Instance{manager: m, principal: InstancePrincipal{spec.ModuleID, InstanceID(id)}, spec: spec, state: Starting, gate: make(chan struct{}), changed: make(chan struct{}), startup: startup, cancelStartup: cancelStartup, lifetime: lifetime, cancelLifetime: cancelLifetime, admissions: make(map[*Admission]struct{}), stopDone: make(chan struct{}), launchDone: make(chan struct{}), credentials: make(map[string]*credentialRecord), drainReady: make(chan struct{})}
	m.instances[spec.ModuleID] = i
	m.mu.Unlock()
	defer func() {
		reason := failureReason(startup, launchErr, "HOOK_FAILED")
		cancelStartup()
		close(i.launchDone)
		if launchErr != nil {
			m.fail(i, reason)
		}
	}()
	guard, err := i.newBrokerGuard()
	if err != nil {
		return i, err
	}
	r := spec.Approval.ResourceLimits
	l := m.config.Limits
	declaration, err := m.options.Host.ImageManifest(startup, spec.ImageDigest)
	if err != nil {
		return i, err
	}
	declaredManifest, err := m.parseImageManifest(declaration)
	if err != nil {
		return i, err
	}
	predictedCore, err := negotiateCore(declaredManifest, spec.Approval)
	if err != nil {
		return i, err
	}
	initialEgress := host.EgressNone
	if predictedCore.EgressPolicy == wire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET {
		initialEgress = host.EgressPublicInternet
	}
	hostSpec := host.LaunchSpec{ModuleID: string(spec.ModuleID), InstanceID: id, ImageDigest: spec.ImageDigest, Entrypoint: spec.Entrypoint, Args: spec.Args, UID: spec.UID, GID: spec.GID, ConfigRevision: spec.ConfigRevision, ApprovalRevision: spec.ApprovalRevision, Resources: host.ResourceLimits{NanoCPUs: int64(r.CpuMillicores) * 1000000, MemoryBytes: int64(r.MemoryBytes), Pids: int64(r.MaxPids), PersistentBytes: int64(r.PersistentBytes), ScratchBytes: int64(r.ScratchBytes), PersistentInodes: l.PersistentInodeLimit, ScratchInodes: l.ScratchInodeLimit, ControlMessageMaxBytes: int64(l.ControlMessageMaxBytes), LogBufferBytes: l.LogBufferBytes, LogFileMaxBytes: l.LogFileMaxBytes, LogRetainedFiles: l.LogRetainedFiles}}
	hostSpec.InitialEgress = initialEgress
	lease, err := m.options.Host.Acquire(startup, hostSpec)
	if err != nil {
		return i, err
	}
	i.mu.Lock()
	i.lease = &lease
	i.mu.Unlock()
	services := InstanceServices{Principal: i.principal, Authorizer: &Authorizer{instance: i}, Credentials: m.credentials, Limits: l, ManagementDirectory: m.config.Host.ManagementDirectory, CredentialBindings: cloneCredentialBindings(spec.CredentialBindings)}
	files, err := m.options.FileTransfer(services)
	if err != nil || files == nil {
		if err == nil {
			err = invalidConfig()
		}
		return i, err
	}
	registrars := []core.HelperRegistrar{func(s grpc.ServiceRegistrar) error {
		wire.RegisterCoreServer(s, &CoreServer{Authorizer: services.Authorizer})
		return nil
	}, files}
	for _, registration := range m.options.Backends {
		register, err := i.registerBackend(registration, services)
		if err != nil || register == nil {
			if err == nil {
				err = invalidConfig()
			}
			return i, err
		}
		registrars = append(registrars, register)
	}
	transport := core.TransportLimits{MaxReceiveBytes: l.ControlMessageMaxBytes, MaxSendBytes: l.ControlMessageMaxBytes}
	bridge, err := core.NewHostPlugin(startup, i.serverFactory, registrars, transport, guard)
	if err != nil {
		return i, err
	}
	if startup.Err() != nil {
		return i, startup.Err()
	}
	factory := host.NewRunnerFactory(m.options.Host, lease)
	primary := &primaryTransport{}
	clientConfig := &plugin.ClientConfig{
		HandshakeConfig:     core.HandshakeConfig(),
		Plugins:             bridge.PluginMap(),
		RunnerFunc:          bindRunnerStartup(factory, startup),
		AutoMTLS:            true,
		SkipHostEnv:         true,
		GRPCBrokerMultiplex: true,
		AllowedProtocols:    []plugin.Protocol{plugin.ProtocolGRPC},
		StartTimeout:        time.Until(deadlineOf(startup)),
		Logger:              hclog.NewNullLogger(),
		Stderr:              io.Discard,
		SyncStdout:          io.Discard,
		SyncStderr:          io.Discard,
		PluginLogBufferSize: l.ControlMessageMaxBytes,
		UnixSocketConfig:    &plugin.UnixSocketConfig{TempDir: lease.IPCPath, Group: strconv.FormatUint(uint64(lease.SocketGID), 10)},
		GRPCDialOptions: []grpc.DialOption{
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(l.ControlMessageMaxBytes), grpc.MaxCallSendMsgSize(l.ControlMessageMaxBytes)),
			guard.DialOption(),
		},
	}
	client := plugin.NewClient(clientConfig)
	i.mu.Lock()
	i.factory = factory
	i.plugin = client
	i.primaryTransport = primary
	i.connectDone = make(chan struct{})
	connectDone := i.connectDone
	i.mu.Unlock()
	type connected struct {
		hooks *core.HookClient
		err   error
	}
	ready := make(chan connected, 1)
	go func() {
		defer close(connectDone)
		// Start fills the actual AutoMTLS certificate and trust configuration.
		// Client() calls Start again idempotently; install the exact delegated
		// credentials only after that configuration exists.
		if _, err := client.Start(); err != nil {
			ready <- connected{err: err}
			return
		}
		if err := startup.Err(); err != nil {
			ready <- connected{err: err}
			return
		}
		if clientConfig.TLSConfig == nil {
			ready <- connected{err: runtimeError(codes.FailedPrecondition, "PROTOCOL_INCOMPATIBLE")}
			return
		}
		clientConfig.GRPCDialOptions = append(clientConfig.GRPCDialOptions, grpc.WithTransportCredentials(&primaryCredentials{
			TransportCredentials: credentials.NewTLS(clientConfig.TLSConfig),
			owner:                primary,
		}))
		rpc, err := client.Client()
		if err != nil {
			ready <- connected{err: err}
			return
		}
		value, err := rpc.Dispense(core.PluginKey)
		if err != nil {
			ready <- connected{err: err}
			return
		}
		hooks, ok := value.(*core.HookClient)
		if !ok {
			ready <- connected{err: runtimeError(codes.FailedPrecondition, "PROTOCOL_INCOMPATIBLE")}
			return
		}
		i.mu.Lock()
		i.hooks = hooks
		i.mu.Unlock()
		ready <- connected{hooks: hooks}
	}()
	var hooks *core.HookClient
	select {
	case <-startup.Done():
		return i, startup.Err()
	case r := <-ready:
		if r.err != nil {
			return i, r.err
		}
		hooks = r.hooks
	}
	manifest, err := callHook(startup, l, func(c context.Context) (*wire.ModuleManifest, error) { return hooks.GetManifest(c) })
	if err != nil {
		return i, err
	}
	if err = m.validateManifest(manifest); err != nil {
		return i, err
	}
	if !proto.Equal(declaredManifest, manifest) {
		return i, runtimeError(codes.FailedPrecondition, "PROTOCOL_INCOMPATIBLE")
	}
	actual, err := m.negotiate(startup, i, manifest)
	if err != nil {
		return i, err
	}
	if actual.EgressPolicy != predictedCore.EgressPolicy {
		return i, runtimeError(codes.FailedPrecondition, "EGRESS_POLICY_MISMATCH")
	}
	i.mu.Lock()
	if i.state != Starting || startup.Err() != nil {
		i.mu.Unlock()
		return i, context.Canceled
	}
	i.grants = proto.Clone(actual).(*wire.Grants)
	i.bound = true
	i.state = Initializing
	i.signalLocked()
	i.mu.Unlock()
	egress := host.EgressNone
	if actual.EgressPolicy == wire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET {
		egress = host.EgressPublicInternet
	}
	if err = m.options.Host.SetEgress(startup, id, egress); err != nil {
		return i, err
	}
	init := &wire.InitContext{ModuleId: string(spec.ModuleID), InstanceId: id, Grants: proto.Clone(actual).(*wire.Grants), PersistentDirectory: host.GuestPersistentPath, ScratchDirectory: host.GuestScratchPath}
	if err = m.stage(startup, i, wire.Stage_STAGE_INIT, init); err != nil {
		return i, err
	}
	for {
		state, err := callHook(startup, l, func(c context.Context) (*wire.Status, error) { return hooks.GetStatus(c) })
		if err != nil {
			return i, err
		}
		if state == nil {
			return i, runtimeError(codes.Internal, "MODULE_REPORTED_FAILURE")
		}
		if state.Readiness == wire.Readiness_READINESS_READY {
			break
		}
		if state.Readiness != wire.Readiness_READINESS_NOT_READY {
			return i, runtimeError(codes.FailedPrecondition, "MODULE_REPORTED_FAILURE")
		}
		timer := time.NewTimer(time.Duration(l.ReadinessPollInterval))
		select {
		case <-startup.Done():
			timer.Stop()
			return i, startup.Err()
		case <-timer.C:
		}
	}
	i.mu.Lock()
	if i.state != Initializing || startup.Err() != nil {
		i.mu.Unlock()
		return i, context.Canceled
	}
	i.state = Ready
	i.activating = true
	i.signalLocked()
	i.mu.Unlock()
	if err = m.stage(startup, i, wire.Stage_STAGE_START, nil); err != nil {
		return i, err
	}
	for _, b := range i.prepared {
		if err = b.Adapter.Activate(startup, i.principal); err != nil {
			return i, err
		}
	}
	i.mu.Lock()
	if i.state != Ready || startup.Err() != nil {
		i.mu.Unlock()
		return i, context.Canceled
	}
	i.state = Running
	i.laneDone = make(chan struct{})
	i.openGateLocked()
	i.mu.Unlock()
	go i.eventLane()
	go i.watchHelperErrors(hooks.HelperErrors())
	return i, nil
}
func deadlineOf(ctx context.Context) time.Time { d, _ := ctx.Deadline(); return d }

// A returned DeadlineExceeded status may belong to a nested helper rather than
// this hook. Retain the original error/status and mark only observed expiration
// of the context that callHook itself supplied.
type hookDeadlineFailure struct {
	cause error
}

func (failure *hookDeadlineFailure) Error() string { return failure.cause.Error() }
func (failure *hookDeadlineFailure) Unwrap() error { return failure.cause }
func (failure *hookDeadlineFailure) GRPCStatus() *status.Status {
	return status.Convert(failure.cause)
}

func callHook[T any](ctx context.Context, l Limits, call func(context.Context) (T, error)) (T, error) {
	bounded, cancel := context.WithTimeout(ctx, time.Duration(l.HookRPCDeadline))
	defer cancel()
	value, err := call(bounded)
	if err != nil && bounded.Err() == context.DeadlineExceeded {
		return value, &hookDeadlineFailure{cause: err}
	}
	return value, err
}
func (m *Manager) stage(ctx context.Context, i *Instance, stage wire.Stage, init *wire.InitContext) error {
	_, err := callHook(ctx, m.config.Limits, func(c context.Context) (struct{}, error) {
		return struct{}{}, i.hooks.OnStage(c, &wire.StageRequest{Stage: stage, InitContext: init})
	})
	return err
}
func failureReason(startup context.Context, err error, fallback string) string {
	if startup.Err() == context.DeadlineExceeded {
		return "STARTUP_DEADLINE_EXCEEDED"
	}
	if err == nil {
		return fallback
	}
	var hookDeadline *hookDeadlineFailure
	if errors.As(err, &hookDeadline) {
		return "HOOK_DEADLINE_EXCEEDED"
	}
	if errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled {
		return "CANCELLED"
	}
	var hostError *host.Error
	if errors.As(err, &hostError) {
		switch hostError.Reason {
		case "HOST_PREREQUISITE_FAILED", "INVALID_CONFIGURATION", "CLEANUP_INCOMPLETE", "MODULE_ALREADY_ACTIVE":
			return hostError.Reason
		}
	}
	for _, d := range status.Convert(err).Details() {
		if x, ok := d.(*wire.ErrorDetail); ok && (x.Origin == wire.ErrorOrigin_ERROR_ORIGIN_FLEXMODULE || x.Origin == wire.ErrorOrigin_ERROR_ORIGIN_BACKEND) {
			switch x.Reason {
			case "PROTOCOL_INCOMPATIBLE", "EGRESS_POLICY_MISMATCH", "REQUIRED_CAPABILITY_DENIED", "RESOURCE_SCOPE_DENIED", "MODULE_REPORTED_FAILURE", "BACKEND_RECONFIGURATION_REQUIRED":
				return x.Reason
			}
		}
	}
	return fallback
}
func (i *Instance) watchHelperErrors(helperErrors <-chan error) {
	select {
	case <-i.lifetime.Done():
		return
	case <-helperErrors:
		// A helper notification and terminal cancellation may both be ready.
		// The selected channel alone cannot classify an expected teardown.
		i.failTransport("BROKER_TRANSPORT_LOST")
	}
}
func (i *Instance) failLocked(reason string) bool {
	if i.state == Stopped || i.cleanupComplete {
		return false
	}
	if i.failure == "" {
		i.failure = reason
		i.incomplete = i.retainedCount
	}
	i.state = Failed
	i.openGateLocked()
	i.cancelStartup()
	for admission := range i.admissions {
		admission.cancel()
	}
	i.cancelLifetime()
	i.queue = nil
	return true
}
func (m *Manager) fail(i *Instance, reason string) {
	i.mu.Lock()
	failed := i.failLocked(reason)
	i.mu.Unlock()
	if failed {
		m.startStop(i, nil)
	}
}
func (m *Manager) Stop(ctx context.Context, id ModuleID) error {
	m.mu.Lock()
	_, installed := m.installed[id]
	i := m.instances[id]
	m.mu.Unlock()
	if !installed {
		return ErrModuleNotInstalled
	}
	if i == nil {
		return nil
	}
	m.startStop(i, ctx)
	i.mu.Lock()
	done := i.stopDone
	i.mu.Unlock()
	select {
	case <-ctx.Done():
		return contextError(ctx)
	case <-done:
		i.mu.Lock()
		defer i.mu.Unlock()
		return i.cleanupError
	}
}
func (m *Manager) startStop(i *Instance, caller context.Context) {
	i.mu.Lock()
	if i.stopStarted {
		i.mu.Unlock()
		return
	}
	i.stopStarted = true
	if i.state == Running {
		deadline := time.Now().Add(time.Duration(m.config.Defaults.DrainDeadline))
		if caller != nil {
			if d, ok := caller.Deadline(); ok && d.Before(deadline) {
				deadline = d
			}
		}
		i.drain, i.cancelDrain = context.WithDeadline(context.Background(), deadline)
		i.state = Draining
		i.openGateLocked()
	} else if i.state != Failed && i.state != Stopped {
		i.state = Failed
		if i.failure == "" {
			i.failure = "CANCELLED"
		}
		i.cancelStartup()
		i.cancelLifetime()
		i.openGateLocked()
	}
	i.mu.Unlock()
	go m.stopInstance(i, caller)
}
func (m *Manager) stopInstance(i *Instance, caller context.Context) {
	defer close(i.stopDone)
	var cleanupErrors []error
	i.mu.Lock()
	drain := i.drain
	i.mu.Unlock()
	var stopCaller func() bool
	if caller != nil && drain != nil {
		stopCaller = context.AfterFunc(caller, func() { i.cancelDrain() })
		defer stopCaller()
	}
	if drain != nil {
		for _, b := range i.prepared {
			if err := b.Adapter.Drain(drain, i.principal); err != nil {
				cleanupErrors = append(cleanupErrors, cleanupPhaseError(CleanupBackendDrain, err))
			}
		}
		close(i.drainReady)
		select {
		case <-i.laneDone:
		case <-drain.Done():
		}
		i.mu.Lock()
		for drain.Err() == nil && len(i.admissions) != 0 {
			changed := i.changed
			i.mu.Unlock()
			select {
			case <-drain.Done():
			case <-changed:
			}
			i.mu.Lock()
		}
		if drain.Err() != nil && (i.retainedCount != 0 || len(i.admissions) != 0) {
			if i.failure == "" {
				i.failure = "DRAIN_DEADLINE_EXCEEDED"
				i.incomplete = i.retainedCount
			}
			i.state = Failed
			i.openGateLocked()
		}
		i.mu.Unlock()
		i.cancelDrain()
	}
	i.beginTerminalCleanup()
	cleanup, cancel := context.WithTimeout(context.Background(), time.Duration(m.config.Limits.TerminationDeadline))
	defer cancel()
	i.mu.Lock()
	failed := i.failure != ""
	i.mu.Unlock()
	if failed {
		if err := m.options.Host.Terminate(cleanup, string(i.principal.InstanceID)); err != nil {
			cleanupErrors = append(cleanupErrors, cleanupPhaseError(CleanupHostTerminate, err))
		}
	}
	select {
	case <-i.launchDone:
	case <-cleanup.Done():
		cleanupErrors = append(cleanupErrors, cleanupPhaseError(CleanupLaunchJoin, runtimeError(codes.Unavailable, "CLEANUP_INCOMPLETE")))
		m.finishCleanup(i, errors.Join(cleanupErrors...))
		return
	}
	i.mu.Lock()
	laneDone := i.laneDone
	hooks := i.hooks
	i.mu.Unlock()
	laneJoined := true
	if laneDone != nil {
		select {
		case <-laneDone:
		case <-cleanup.Done():
			laneJoined = false
			cleanupErrors = append(cleanupErrors, cleanupPhaseError(CleanupCallbackJoin, runtimeError(codes.Unavailable, "CLEANUP_INCOMPLETE")))
		}
	}
	i.mu.Lock()
	safeStop := laneJoined && i.failure == "" && !i.callbackActive
	i.mu.Unlock()
	if safeStop && hooks != nil {
		if err := m.stage(cleanup, i, wire.Stage_STAGE_STOP, nil); err != nil {
			cleanupErrors = append(cleanupErrors, cleanupPhaseError(CleanupStopHook, err))
		}
	}
	if hooks != nil {
		if err := hooks.Close(); err != nil {
			cleanupErrors = append(cleanupErrors, cleanupPhaseError(CleanupHelperClose, err))
		}
	}
	// This operation is independent of go-plugin's client mutex. In particular,
	// muxDial may ignore ctx while Client.Client holds that mutex.
	if err := m.options.Host.Terminate(cleanup, string(i.principal.InstanceID)); err != nil {
		cleanupErrors = append(cleanupErrors, cleanupPhaseError(CleanupHostTerminate, err))
	}
	i.mu.Lock()
	client, factory, connectDone, primary := i.plugin, i.factory, i.connectDone, i.primaryTransport
	if client != nil && i.killDone == nil {
		i.killDone = make(chan struct{})
		go func() { client.Kill(); close(i.killDone) }()
	}
	killDone := i.killDone
	i.mu.Unlock()
	i.mu.Lock()
	revokeCredentialsLocked(i)
	i.mu.Unlock()
	// Backend workers may own upload readers and credential leases. Cancel and
	// release them before waiting for those stores' physical reclamation.
	if err := i.cleanupRegisteredBackends(cleanup); err != nil {
		cleanupErrors = append(cleanupErrors, cleanupPhaseError(CleanupBackend, err))
	}
	if err := m.options.FileCleanup(cleanup, i.principal); err != nil {
		cleanupErrors = append(cleanupErrors, cleanupPhaseError(CleanupFiles, err))
	}
	if err := m.credentials.RevokeInstance(cleanup, i.principal); err != nil {
		cleanupErrors = append(cleanupErrors, cleanupPhaseError(CleanupCredentials, err))
	}
	transportClosed := true
	for _, pending := range []struct {
		phase CleanupPhase
		done  <-chan struct{}
	}{{CleanupPluginJoin, killDone}, {CleanupConnectJoin, connectDone}} {
		if pending.done != nil {
			select {
			case <-pending.done:
			case <-cleanup.Done():
				transportClosed = false
				cleanupErrors = append(cleanupErrors, cleanupPhaseError(pending.phase, runtimeError(codes.Unavailable, "CLEANUP_INCOMPLETE")))
			}
		}
	}
	if transportClosed {
		i.mu.Lock()
		lateHooks := i.hooks
		i.mu.Unlock()
		if lateHooks != nil && lateHooks != hooks {
			if err := lateHooks.Close(); err != nil {
				cleanupErrors = append(cleanupErrors, cleanupPhaseError(CleanupHelperClose, err))
			}
		}
	}
	if err := i.waitControls(cleanup); err != nil {
		cleanupErrors = append(cleanupErrors, cleanupPhaseError(CleanupControls, err))
	}
	if transportClosed {
		if err := primary.close(cleanup); err != nil {
			cleanupErrors = append(cleanupErrors, cleanupPhaseError(CleanupTransport, err))
			transportClosed = false
		}
	}
	if transportClosed && factory != nil {
		if err := factory.CloseTransport(); err != nil {
			cleanupErrors = append(cleanupErrors, cleanupPhaseError(CleanupTransport, err))
			transportClosed = false
		}
	}
	if transportClosed && len(cleanupErrors) == 0 {
		if err := m.options.Host.Release(cleanup, string(i.principal.InstanceID)); err != nil {
			cleanupErrors = append(cleanupErrors, cleanupPhaseError(CleanupHostRelease, err))
		}
	} else {
		cleanupErrors = append(cleanupErrors, runtimeError(codes.Unavailable, "CLEANUP_INCOMPLETE"))
	}
	m.finishCleanup(i, errors.Join(cleanupErrors...))
}
func (m *Manager) finishCleanup(i *Instance, err error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.bound = false
	i.cleanupError = err
	i.cleanupComplete = err == nil
	if err == nil && i.failure == "" {
		i.state = Stopped
	} else {
		i.state = Failed
		if i.failure == "" {
			i.failure = "CLEANUP_INCOMPLETE"
		}
	}
	if i.retainedCount > 0 && i.incomplete == 0 {
		i.incomplete = i.retainedCount
	}
	i.queue = nil
	if err == nil {
		i.retainedCount = 0
		i.retainedBytes = 0
	}
	i.signalLocked()
}
func (m *Manager) Reconcile(ctx context.Context) error {
	m.reconcileMu.Lock()
	defer m.reconcileMu.Unlock()
	var failures []error
	for id := range m.installed {
		m.mu.Lock()
		i := m.instances[id]
		m.mu.Unlock()
		if i == nil {
			continue
		}
		i.mu.Lock()
		retry := false
		if i.state == Failed && !i.cleanupComplete && i.stopStarted {
			select {
			case <-i.stopDone:
				i.stopStarted = false
				i.stopDone = make(chan struct{})
				i.drain = nil
				retry = true
			default:
			}
		}
		i.mu.Unlock()
		if retry {
			m.startStop(i, nil)
			i.mu.Lock()
			done := i.stopDone
			i.mu.Unlock()
			select {
			case <-ctx.Done():
				return contextError(ctx)
			case <-done:
			}
			i.mu.Lock()
			err := i.cleanupError
			i.mu.Unlock()
			if err != nil {
				failures = append(failures, err)
			}
		}
	}
	if err := m.options.Host.Reconcile(ctx); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func (i *Instance) waitControls(ctx context.Context) error {
	i.mu.Lock()
	for i.controls != 0 {
		changed := i.changed
		i.mu.Unlock()
		select {
		case <-ctx.Done():
			return contextError(ctx)
		case <-changed:
		}
		i.mu.Lock()
	}
	i.mu.Unlock()
	return nil
}

// Register may allocate instance-bound state even when the manifest never
// selects this backend. Record ownership before invoking any backend callback.
func (i *Instance) registerBackend(registration BackendRegistration, services InstanceServices) (core.HelperRegistrar, error) {
	i.mu.Lock()
	i.registered = append(i.registered, registration)
	i.mu.Unlock()
	return registration.Register(services)
}

// The launch operation is joined before cleanup, so no later registration can
// acquire resources after this pass. Cleanup tolerates partial registration and
// repeated invocation; one adapter failure never skips another registered owner.
func (i *Instance) cleanupRegisteredBackends(ctx context.Context) error {
	i.mu.Lock()
	registered := i.registered
	i.mu.Unlock()
	var failures []error
	for _, registration := range registered {
		if err := registration.Adapter.Cleanup(ctx, i.principal); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
