//go:build linux

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/provision"
	"github.com/thirdscam/chatanium/internal/runtime"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type OwnedSession struct{ state *ownedSession }
type ownedSession struct {
	mu                                  sync.Mutex
	id                                  RuntimeInstallationID
	manifest                            host.InstallationManifest
	store                               *host.Store
	lease                               *host.InstallationLease
	systemd                             *host.Systemd
	owner, worker                       host.UnitIdentity
	supervisor                          *host.Supervisor
	images                              *host.ImageManager
	storage                             *host.Storage
	network                             *host.Network
	preparing                           sync.WaitGroup
	taskCancel                          map[string]context.CancelFunc
	cleanupEvidence                     host.CleanupEvidence
	purgeRetirements                    map[string]bool
	workerReferences                    []host.GenerationReference
	workerRevision                      string
	recoveryOnly                        bool
	startupWG                           sync.WaitGroup
	startupCancel                       context.CancelFunc
	initialized                         bool
	config                              runtime.Config
	input, output, diagnostics          *os.File
	observationOutput                   *os.File
	observationSource, observationFlags int
	events                              chan workerRead
	done, workerDone                    chan struct{}
	workerLedger                        string
	workerFinished                      sync.Once
	readerWG                            sync.WaitGroup
	watcherWG                           sync.WaitGroup
	workerCancel                        context.CancelFunc
	networkCancel                       context.CancelFunc
	operation                           string
	ready, terminal, closing            bool
	report                              CleanupReport
	drainErr                            error
}
type workerRead struct {
	event WorkerEvent
	err   error
}

func imageConfig(m host.InstallationManifest, b bundle.Verified, u host.UnitIdentity, input func(context.Context, provision.ApprovedImageInput) (io.ReadCloser, io.ReadCloser, error)) host.ImageManagerConfig {
	if input == nil {
		input = privateTaskInput
	}
	return host.ImageManagerConfig{Owner: u, Bundle: b, Preparer: m.Identities.Preparer, Limits: provision.PrepareLimits{NanoCPUs: 1e9, MemoryBytes: 512 << 20, Tasks: 64, InputBytes: m.Budget.SourceBytes, ExpandedBytes: m.Budget.PreparationBytes, OutputBytes: m.Budget.CacheBytes, Inodes: m.Budget.PreparationInodes, JSONBytes: 16 << 20, DescriptorCount: 4096, IndexDepth: 32, Deadline: 5 * time.Minute}, TaskInput: input}
}
func installedBundle(ctx context.Context, m host.InstallationManifest) (bundle.Verified, error) {
	if !provision.ValidDigest(m.BundleDigest) {
		return bundle.Verified{}, errors.New("invalid durable bundle identity")
	}
	raw, e := readProtected(filepath.Join(m.Paths.EngineRoot, m.BundleDigest[7:], "manifest.json"), bundle.MaxManifestBytes)
	if e != nil {
		return bundle.Verified{}, e
	}
	bm, e := bundle.VerifyManifest(raw)
	if e != nil {
		return bundle.Verified{}, e
	}
	if bm.Digest != m.BundleDigest {
		return bundle.Verified{}, errors.New("installed bundle identity mismatch")
	}
	return bundle.VerifyDirectory(ctx, filepath.Join(m.Paths.EngineRoot, m.BundleDigest[7:]), bm)
}
func acquireSession(ctx context.Context, id RuntimeInstallationID, mode RunMode) (result *ownedSession, retErr error) {
	session, e := openOwner(ctx, id, mode)
	if e != nil {
		return nil, e
	}
	transferred := false
	defer func() {
		if retErr == nil || transferred {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		var failure error
		if session.supervisor != nil {
			_, failure = DrainOwnedSession(cleanup, OwnedSession{session})
		} else {
			if session.images != nil {
				failure = session.images.Recover(cleanup)
			}
			if session.storage != nil {
				quota, qe := session.storage.ReclaimEvidence(cleanup)
				failure = errors.Join(failure, qe, session.storage.Close())
				proof, pe := session.systemd.RecoverHelpers(cleanup)
				failure = errors.Join(failure, pe, session.store.AssertRemovable(cleanup))
				proof.QuotaReclaimed = quota.QuotaReclaimed
				if failure == nil {
					failure = host.DetachBacking(cleanup, session.manifest, session.store, session.systemd, proof)
				}
			}
		}
		failure = errors.Join(failure, session.store.RequireRecovery(cleanup, "owner construction did not complete"), closeMaintenance(session))
		retErr = errors.Join(retErr, failure)
	}()
	if session.manifest.ActiveRevision == "" {
		return nil, errors.New("initialization has no active approved revision")
	}
	m, c := session.manifest, session.config
	verified, e := installedBundle(ctx, m)
	if e != nil {
		return nil, e
	}
	if e = host.AttachBacking(ctx, m, session.store, session.systemd); e != nil {
		return nil, e
	}
	sc := supervisorConfig(m, c)
	session.storage, e = host.NewStorage(ctx, sc, session.store, session.systemd)
	if e != nil {
		return nil, e
	}
	session.images, e = host.NewImageManager(imageConfig(m, verified, session.owner, nil), session.store, session.systemd, session.storage)
	if e != nil {
		return nil, e
	}
	if e = session.images.Recover(ctx); e != nil {
		return nil, e
	}
	session.workerReferences, e = staleWorkerReferences(ctx, session.store)
	if e != nil {
		return nil, e
	}
	nc := host.NetworkConfig{Profile: profile(c), IPv4Pool: c.Host.Network.IPv4Pool, IPv6Pool: c.Host.Network.IPv6Pool, InventoryRevision: c.Host.Network.InventoryRevision, Uplink4: c.Host.Network.Uplink4, Uplink6: c.Host.Network.Uplink6, Source4: c.Host.Network.Source4, Source6: c.Host.Network.Source6, Resolvers: c.Host.Network.Resolvers, HostPublicAddresses: c.Host.Network.HostPublicAddresses, InternalPrefixes: append(append([]string{}, c.Host.Network.InternalPrefixes...), c.Host.Network.InfrastructurePrefixes...), MetadataPrefixes: c.Host.Network.MetadataDestinations, OperationTimeout: sc.OperationTimeout}
	nc.RunRoot = m.Paths.RunRoot
	session.network, e = host.NewNetwork(ctx, nc, session.store, session.systemd)
	if e != nil {
		return nil, e
	}
	platform, e := host.NewGvxPlatform(host.GvxPlatformConfig{Owner: session.owner, Bundle: verified, Sandbox: m.Identities.Sandbox, StartupDeadline: time.Duration(c.Defaults.StartupDeadline), OperationTimeout: sc.OperationTimeout, TerminationDeadline: time.Duration(c.Limits.TerminationDeadline)}, session.store, session.systemd, session.storage, session.network, session.images)
	if e != nil {
		return nil, e
	}
	session.supervisor, e = host.NewSupervisor(ctx, sc, platform, session.store, session.lease)
	if e != nil {
		return nil, e
	}
	if e = ensureWorkerSocketProjection(ctx, session.store, session.manifest, session.cleanupEvidence); e != nil {
		return nil, e
	}
	monitorCtx, monitorCancel := context.WithCancel(context.Background())
	session.networkCancel = monitorCancel
	monitored := make(chan error, 1)
	go func() {
		err := session.network.Monitor(monitorCtx, func(o host.Ownership, cause error) {
			cleanup, cancel := context.WithTimeout(context.Background(), sc.OperationTimeout)
			defer cancel()
			platform.Terminate(cleanup, o)
		})
		monitored <- err
		if monitorCtx.Err() == nil {
			session.workerFinished.Do(func() { close(session.workerDone) })
		}
	}()
	select {
	case <-session.network.Ready():
	case err := <-monitored:
		if err == nil {
			err = errors.New("network monitor ended before readiness")
		}
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if (m.State == "RECOVERY_REQUIRED" && m.PendingRevision == "") || len(session.workerReferences) > 0 {
		session.recoveryOnly = true
		report, cleanup := DrainOwnedSession(ctx, OwnedSession{session})
		if cleanup != nil || !report.Complete {
			return nil, errors.Join(cleanup, host.ErrCleanupIncomplete)
		}
		transferred = true
		if e = closeMaintenance(session); e != nil {
			return nil, e
		}
		return acquireSession(ctx, id, mode)
	}
	return session, nil
}
func Run(ctx context.Context, id RuntimeInstallationID, mode RunMode) error {
	return RunWithOptions(ctx, id, mode, RunOptions{})
}
func RunService(ctx context.Context, id RuntimeInstallationID) error {
	return RunWithOptions(ctx, id, Service, RunOptions{})
}
func RunWithOptions(ctx context.Context, id RuntimeInstallationID, mode RunMode, options RunOptions) (retErr error) {
	if mode != Foreground && mode != Service {
		return errors.New("invalid run mode")
	}
	if options.Duration < 0 {
		return errors.New("negative duration")
	}
	if mode == Service && (options.DevelopmentMode || options.DevelopmentRevision != "" || options.DevelopmentSocket != "" || len(options.DevelopmentImages) > 0) {
		return errors.New("service cannot inherit development options")
	}
	if options.DevelopmentRevision != "" && (mode != Foreground || !options.DevelopmentMode) {
		return errors.New("development revision requires foreground development mode")
	}
	s, e := acquireSession(ctx, id, mode)
	if e != nil {
		return e
	}
	var cancelServe context.CancelFunc
	defer func() {
		_, cleanup := DrainOwnedSession(context.Background(), OwnedSession{s})
		if cleanup != nil && !errors.Is(retErr, cleanup) {
			retErr = errors.Join(retErr, cleanup)
		}
		if cancelServe != nil {
			cancelServe()
		}
		retErr = errors.Join(retErr, closeMaintenance(s))
	}()
	desired, admit, e := runIntent(mode, s.manifest.DesiredRunState)
	if e != nil {
		return e
	}
	if mode == Foreground {
		if e = s.store.SetDesired(ctx, desired, newID()); e != nil {
			return e
		}
		s.manifest.DesiredRunState = desired
	}
	if !admit {
		return nil
	}
	if s.manifest.State != "READY" || s.manifest.PendingRevision != "" {
		return errors.New("installation requires an explicit approved recovery/update before admission")
	}
	if options.DevelopmentMode {
		if e = s.config.Host.ValidateDevelopmentSocket(options.DevelopmentSocket); e != nil {
			return e
		}
	}
	for _, identity := range []host.NumericIdentity{s.manifest.Identities.App, s.manifest.Identities.Sandbox, s.manifest.Identities.Preparer} {
		if e = validateAccount(identity); e != nil {
			return e
		}
	}
	revision, e := s.selectWorkerRevision(ctx, mode, options)
	if e != nil {
		return e
	}
	s.workerRevision = revision.ID
	secretValues, e := loadSecrets(s.manifest.Paths.Secrets)
	if e != nil {
		return e
	}
	init := WorkerInit{Version: 1, RuntimeInstallationID: string(id), Revision: revision.ID, EpochID: s.supervisor.EpochID(), Config: revision.Config, Host: host.ClientConfig{SocketPath: host.WorkerControlSocketPath(s.manifest), SupervisorUID: 0, MaxMessageBytes: s.config.Limits.ControlMessageMaxBytes, OperationTimeout: time.Duration(s.config.Limits.HostOperationDeadline)}, Options: options, Secrets: secretValues}
	if e = ValidateWorkerInit(init); e != nil {
		return e
	}
	if _, e = encodedControl(WorkerCommand{Version: 1, Type: "INIT", Init: &init}); e != nil {
		return e
	}
	if e = s.openObservationOutput(); e != nil {
		return e
	}
	management, e := s.serveManagement()
	if e != nil {
		return e
	}
	defer management.Close()
	serveCtx, cancel := context.WithCancel(context.Background())
	cancelServe = cancel
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.supervisor.Serve(serveCtx) }()
	if e = s.startWorker(ctx, init); e != nil {
		return e
	}
	var timer <-chan time.Time
	if options.Duration > 0 {
		duration := time.NewTimer(options.Duration)
		defer duration.Stop()
		timer = duration.C
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer:
		return nil
	case <-s.done:
		return s.drainErr
	case e = <-serveErr:
		return e
	case <-s.workerDone:
		return errors.New("worker exited")
	}
}
func (s *ownedSession) startWorker(ctx context.Context, init WorkerInit) error {
	startup, cancel := context.WithTimeout(ctx, time.Duration(s.config.Defaults.StartupDeadline))
	defer cancel()
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return errors.New("owner is already draining")
	}
	s.startupCancel = cancel
	s.startupWG.Add(1)
	s.mu.Unlock()
	defer s.startupWG.Done()
	stdinR, stdinW, e := os.Pipe()
	if e != nil {
		return e
	}
	stdoutR, stdoutW, e := os.Pipe()
	if e != nil {
		stdinR.Close()
		stdinW.Close()
		return e
	}
	stderrR, stderrW, e := os.Pipe()
	if e != nil {
		stdinR.Close()
		stdinW.Close()
		stdoutR.Close()
		stdoutW.Close()
		return e
	}
	s.input = stdinW
	s.output = stdoutR
	s.diagnostics = stderrR
	defer stdinR.Close()
	defer stdoutW.Close()
	defer stderrW.Close()
	s.readerWG.Add(2)
	go func() {
		defer s.readerWG.Done()
		ready, terminal := false, false
		for {
			v, e := ReadWorkerEvent(stdoutR)
			s.mu.Lock()
			operation := s.operation
			s.mu.Unlock()
			if e == nil {
				if terminal {
					e = errors.New("worker message after terminal event")
				} else {
					switch v.Type {
					case "READY":
						if ready {
							e = errors.New("duplicate worker READY")
						} else {
							ready = true
						}
					case "OBSERVATION":
						if e = s.forwardObservation(v.Observation); e == nil {
							continue
						}
					case "DRAINED":
						if operation == "" || v.OperationID != operation {
							e = errors.New("worker drain binding mismatch")
						} else {
							terminal = true
						}
					case "FAILED":
						if (operation == "") != (v.OperationID == "") || operation != "" && v.OperationID != operation {
							e = errors.New("worker failure binding mismatch")
						}
						terminal = true
					}
				}
			}
			select {
			case s.events <- workerRead{v, e}:
			case <-s.done:
				return
			}
			if e != nil {
				s.workerFinished.Do(func() { close(s.workerDone) })
				return
			}
		}
	}()
	go func() {
		defer s.readerWG.Done()
		var slab [4096]byte
		for {
			_, e := stderrR.Read(slab[:])
			if e != nil {
				return
			}
		}
	}()
	generation := newID()
	name := "chatanium-worker-" + generation + ".service"
	if e = s.storage.VerifyApp(startup); e != nil {
		return e
	}
	service, e := s.systemd.WorkerService(startup, s.owner, name, generation, workerLimits(), time.Duration(s.config.Limits.TerminationDeadline))
	if e != nil {
		return e
	}
	ledger, e := recordIntent(startup, s.store, "unit", name, host.ProvisionProperties{Name: name, Revision: init.Revision, ProductCreated: true}, false)
	if e != nil {
		return e
	}
	s.workerLedger = ledger
	files := host.StandardFiles{Stdin: stdinR, Stdout: stdoutW, Stderr: stderrW}
	var v host.UnitObservation
	if init.Options.DevelopmentRevision != "" {
		v, e = s.systemd.StartDevelopmentWorker(startup, service, files, init.Options.DevelopmentRevision)
	} else {
		v, e = s.systemd.StartOwned(startup, service, files)
	}
	if e != nil {
		return e
	}
	s.worker = v.Unit
	if e = observeWorkerLedger(startup, s.store, ledger, name, init.Revision, &v.Unit); e != nil {
		return e
	}
	if e = s.supervisor.BindWorker(startup, v.Unit); e != nil {
		return e
	}
	waitCtx, workerCancel := context.WithCancel(context.Background())
	s.workerCancel = workerCancel
	s.watcherWG.Add(1)
	go func() {
		defer s.watcherWG.Done()
		defer workerCancel()
		_, err := s.systemd.Wait(waitCtx, v.Unit)
		if err == nil {
			terminalCtx, cancel := context.WithTimeout(context.Background(), time.Duration(s.config.Limits.HostOperationDeadline))
			defer cancel()
			err = observeWorkerLedger(terminalCtx, s.store, ledger, name, init.Revision, &v.Unit)
			if err == nil {
				err = s.systemd.ReleaseReference(terminalCtx, v.Unit)
			}
		}
		s.workerFinished.Do(func() { close(s.workerDone) })
	}()
	written := make(chan error, 1)
	go func() { written <- WriteWorkerCommand(stdinW, WorkerCommand{Version: 1, Type: "INIT", Init: &init}) }()
	select {
	case e = <-written:
		if e != nil {
			return e
		}
		s.initialized = true
	case <-startup.Done():
		stdinW.Close()
		return startup.Err()
	}
	for {
		select {
		case <-startup.Done():
			return startup.Err()
		case <-s.workerDone:
			return errors.New("worker exited before READY")
		case r := <-s.events:
			if r.err != nil {
				return r.err
			}
			switch r.event.Type {
			case "READY":
				s.ready = true
				return nil
			case "FAILED":
				return errors.New("worker startup failed")
			default:
				return errors.New("worker event out of order")
			}
		}
	}
}
func DrainOwnedSession(_ context.Context, owned OwnedSession) (CleanupReport, error) {
	s := owned.state
	if s == nil {
		return CleanupReport{}, errors.New("invalid owned session")
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		<-s.done
		return s.report, s.drainErr
	}
	s.closing = true
	for _, cancel := range s.taskCancel {
		cancel()
	}
	if s.startupCancel != nil {
		s.startupCancel()
	}
	s.mu.Unlock()
	defer close(s.done)
	budget, budgetErr := cleanupTimeout(s.config)
	if budgetErr != nil {
		budget = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	r := CleanupReport{InstallationID: s.id, DesiredRunState: "STOPPED", ObservedState: "unknown"}
	var operationErr, cleanupErr error
	operationErr = budgetErr
	operationErr = errors.Join(operationErr, s.closeObservationOutput())
	if !s.recoveryOnly {
		if e := s.store.SetDesired(ctx, "STOPPED", newID()); e != nil {
			cleanupErr = errors.Join(cleanupErr, e)
		}
	} else {
		r.DesiredRunState = s.manifest.DesiredRunState
	}
	preparationsDone := make(chan struct{})
	go func() { s.preparing.Wait(); s.startupWG.Wait(); close(preparationsDone) }()
	select {
	case <-preparationsDone:
	case <-ctx.Done():
		cleanupErr = errors.Join(cleanupErr, ctx.Err())
	}
	if s.worker.Name != "" && s.initialized {
		s.mu.Lock()
		s.operation = newID()
		operation := s.operation
		s.mu.Unlock()
		remaining := time.Duration(s.config.Defaults.DrainDeadline)
		writeErr := make(chan error, 1)
		go func() {
			writeErr <- WriteWorkerCommand(s.input, WorkerCommand{Version: 1, Type: "DRAIN", OperationID: operation, RemainingNS: int64(remaining)})
		}()
		timer := time.NewTimer(remaining)
		drained := false
		for !drained {
			select {
			case e := <-writeErr:
				if e != nil {
					operationErr = errors.Join(operationErr, e)
					drained = true
				}
				writeErr = nil
			case read := <-s.events:
				if read.err != nil {
					operationErr = errors.Join(operationErr, read.err)
					drained = true
				} else if read.event.Type == "DRAINED" && read.event.OperationID == operation {
					for _, m := range read.event.Drain.Modules {
						if !m.CleanupComplete {
							operationErr = errors.Join(operationErr, errors.New("worker module cleanup incomplete"))
						}
					}
					for range read.event.Drain.Failures {
						operationErr = errors.Join(operationErr, errors.New("worker drain reported failure"))
					}
					drained = true
				} else if read.event.Type == "READY" {
					continue
				} else {
					operationErr = errors.Join(operationErr, errors.New("worker drain protocol failure"))
					drained = true
				}
			case <-timer.C:
				operationErr = errors.Join(operationErr, errors.New("worker drain deadline exceeded"))
				drained = true
			}
		}
		timer.Stop()
	}
	if e := s.supervisor.Drain(ctx); e != nil {
		cleanupErr = errors.Join(cleanupErr, e)
	}
	if s.worker.Name != "" {
		stopErr := s.systemd.Stop(ctx, s.worker)
		_, waitErr := s.systemd.Wait(ctx, s.worker)
		operationErr = errors.Join(operationErr, stopErr, waitErr)
	}
	for _, f := range []*os.File{s.input, s.output, s.diagnostics} {
		if f != nil {
			f.Close()
		}
	}
	if s.workerCancel != nil {
		s.workerCancel()
	}
	joined := make(chan struct{})
	go func() { s.readerWG.Wait(); s.watcherWG.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-ctx.Done():
		cleanupErr = errors.Join(cleanupErr, ctx.Err())
	}
	if s.networkCancel != nil {
		s.networkCancel()
	}
	if s.network != nil {
		cleanupErr = errors.Join(cleanupErr, s.network.Close())
	}
	if s.images != nil {
		cleanupErr = errors.Join(cleanupErr, s.images.Recover(ctx))
	}
	var quota host.CleanupEvidence
	if s.storage != nil {
		var qe error
		quota, qe = s.storage.ReclaimEvidence(ctx)
		cleanupErr = errors.Join(cleanupErr, qe, s.storage.Close())
	}
	evidence, e := s.systemd.RecoverHelpers(ctx)
	cleanupErr = errors.Join(cleanupErr, e)
	evidence.QuotaReclaimed = quota.QuotaReclaimed
	if cleanupErr == nil {
		cleanupErr = recoverWorkerLedgers(ctx, s, evidence)
		if cleanupErr == nil {
			cleanupErr = host.DetachBacking(ctx, s.manifest, s.store, s.systemd, evidence)
		}
		if cleanupErr == nil {
			cleanupErr = completeEvidence(ctx, s.manifest, &evidence)
		}
		if cleanupErr == nil {
			for _, ref := range s.workerReferences {
				if e = s.store.ReleaseGeneration(ctx, ref.Kind, ref.ID, ref.Claim, evidence); e != nil {
					cleanupErr = errors.Join(cleanupErr, e)
				}
			}
		}
		if cleanupErr == nil && s.recoveryOnly && s.manifest.State == "RECOVERY_REQUIRED" {
			cleanupErr = s.store.CompleteRecovery(ctx, evidence)
		}
	}
	r.Complete = cleanupErr == nil
	if r.Complete {
		r.ObservedState = "stopped"
	} else {
		s.store.RequireRecovery(ctx, "owner cleanup incomplete")
	}
	all := errors.Join(operationErr, cleanupErr)
	if operationErr != nil {
		r.Failures = append(r.Failures, OperationFailure{Phase: "worker-drain", Code: "WORKER_DRAIN_FAILED", Message: operationErr.Error()})
	}
	if cleanupErr != nil {
		r.Failures = append(r.Failures, OperationFailure{Phase: "cleanup", Code: "CLEANUP_INCOMPLETE", Message: cleanupErr.Error()})
	}
	s.mu.Lock()
	s.report = r
	s.drainErr = all
	s.cleanupEvidence = evidence
	s.mu.Unlock()
	return r, all
}
func completeEvidence(ctx context.Context, m host.InstallationManifest, e *host.CleanupEvidence) error {
	storage, err := host.VerifyDetached(ctx, m)
	if err != nil {
		return err
	}
	e.MountsAbsent = storage.MountsAbsent
	e.OpenReferencesAbsent = e.OpenReferencesAbsent && storage.OpenReferencesAbsent
	if !e.JobsAbsent || !e.ProcessesAbsent || !e.TransportsClosed || !e.MountsAbsent || !e.OpenReferencesAbsent {
		return host.ErrCleanupIncomplete
	}
	return nil
}
func jsonSecrets(sources []SecretSource) ([]byte, error) {
	seen := map[string]bool{}
	for _, s := range sources {
		key := s.BackendID + ":" + s.SecretName
		if !validID(s.BackendID) || !validID(s.SecretName) || seen[key] {
			return nil, errors.New("invalid secret binding")
		}
		seen[key] = true
		switch s.SourceKind {
		case "env":
			if !envName(s.SourceReference) {
				return nil, errors.New("invalid secret environment reference")
			}
		case "protected-file":
			if e := trustedPath(s.SourceReference, false); e != nil {
				return nil, e
			}
		default:
			return nil, errors.New("unknown explicit secret source")
		}
	}
	return json.Marshal(sources)
}
func envName(s string) bool {
	if s == "" {
		return false
	}
	for n, c := range s {
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || n > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func loadSecrets(path string) (map[string]string, error) {
	raw, e := readProtected(path, WorkerSecretMaxBytes)
	if e != nil {
		return nil, e
	}
	var sources []SecretSource
	if e = gvxcontract.DecodeStrict(raw, WorkerSecretMaxBytes, 8, &sources); e != nil {
		return nil, e
	}
	if _, e = jsonSecrets(sources); e != nil {
		return nil, e
	}
	out := map[string]string{}
	total := 0
	for _, s := range sources {
		var value string
		if s.SourceKind == "env" {
			v, ok := os.LookupEnv(s.SourceReference)
			if !ok {
				return nil, errors.New("explicit secret source missing")
			}
			value = v
		} else {
			v, e := readProtected(s.SourceReference, WorkerSecretMaxBytes)
			if e != nil {
				return nil, e
			}
			value = string(v)
		}
		total += len(value)
		if total > WorkerSecretMaxBytes {
			return nil, errors.New("secret input exceeds bound")
		}
		out[s.BackendID+":"+s.SecretName] = value
	}
	return out, nil
}
