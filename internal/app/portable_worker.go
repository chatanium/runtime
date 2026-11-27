package app

import (
	"context"
	"errors"
	"io"
	"slices"
	"time"

	discordbackend "github.com/thirdscam/chatanium/internal/backend/discord"
	"github.com/thirdscam/chatanium/internal/discordacl"
	"github.com/thirdscam/chatanium/internal/portable/session"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	"github.com/thirdscam/chatanium/internal/runtime/upload"
)

// RunWorker accepts an explicit portable-mode argument on every native host.
// The argument-free invocation is retained for Linux's existing v1 supervisor.
func RunWorker(ctx context.Context, input io.Reader, output io.Writer, diagnostics io.Writer, args ...string) error {
	if len(args) == 1 && args[0] == session.WorkerArg {
		return RunPortableWorker(ctx, input, output)
	}
	if len(args) != 0 {
		return errors.New("unsupported worker invocation")
	}
	return runLegacyWorker(ctx, input, output, diagnostics)
}

type workerDrain struct {
	deadline time.Time
	err      error
}

// RunPortableWorker builds the real core-v2 Manager from a single private INIT.
// The worker has only runtime RPC authority and no engine or management handle.
func RunPortableWorker(ctx context.Context, input io.Reader, output io.Writer) error {
	in, inOK := input.(io.ReadCloser)
	out, outOK := output.(io.WriteCloser)
	if !inOK || !outOK {
		return errors.New("portable worker requires closeable control pipes")
	}
	stopInput := context.AfterFunc(ctx, func() { _ = in.Close() })
	defer stopInput()
	defer in.Close()
	init, err := session.ReadWorkerInit(in)
	if err != nil {
		return errors.Join(errors.New("portable worker requires INIT"), reportWorkerFailure(out, "INVALID_INIT"))
	}
	config, err := runtime.DecodeConfig(init.Config)
	if err != nil || config.Host.Format != runtime.PortableFormat || len(config.Modules) == 0 && len(config.Backends) != 0 {
		return errors.Join(errors.New("portable worker configuration rejected"), reportWorkerFailure(out, "INVALID_CONFIGURATION"))
	}
	if !matchCapturedSecrets(config, init.Secrets) {
		return errors.Join(errors.New("portable worker secret bindings rejected"), reportWorkerFailure(out, "INVALID_SECRET_BINDINGS"))
	}
	client, err := session.NewClient(init.Endpoint, init.Credentials, config.Host.RuntimeInstallationID)
	if err != nil {
		return errors.Join(err, reportWorkerFailure(out, "INVALID_SUPERVISOR_SESSION"))
	}
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	readDone := make(chan struct{})
	acl := make(chan session.WorkerACLChange, 1)
	var command workerDrain
	go func() {
		defer cancel()
		defer close(readDone)
		for {
			control, err := session.ReadWorkerControl(in)
			if err != nil || !control.DrainDeadline.IsZero() {
				command = workerDrain{deadline: control.DrainDeadline, err: err}
				return
			}
			select {
			case acl <- control.ACLChange:
			default:
				command.err = errors.New("unexpected queued worker ACL change")
				return
			}
		}
	}()
	defer func() { _ = in.Close(); <-readDone }()

	// Even if the supervisor stops reading while DRAIN arrives, blocked event
	// writes may not keep the worker alive beyond its bounded shutdown window.
	shutdownBudget := time.Duration(config.Defaults.DrainDeadline) + time.Duration(config.Limits.TerminationDeadline)
	watchDone := make(chan struct{})
	watchExit := make(chan struct{})
	go func() {
		defer close(watchExit)
		select {
		case <-watchDone:
			return
		case <-life.Done():
		}
		deadline := time.Now().Add(shutdownBudget)
		select {
		case <-readDone:
			if command.err == nil && command.deadline.Before(deadline) {
				deadline = command.deadline
			}
		default:
		}
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case <-watchDone:
		case <-timer.C:
			_ = out.Close()
			_ = in.Close()
		}
	}()
	defer func() { close(watchDone); <-watchExit }()

	work := portableWork{config: config}
	workErr := work.run(life, client, init.Secrets, init.DiscordACL, acl, out)
	deadline := time.Now().Add(shutdownBudget)
	var requested workerDrain
	select {
	case <-readDone:
		requested = command
		if requested.err == nil && requested.deadline.Before(deadline) {
			deadline = requested.deadline
		}
	default:
	}
	cancel()
	clean := work.close(deadline)
	modules := work.statuses(nil)
	if !clean {
		workErr = errors.Join(workErr, errors.New("portable worker cleanup incomplete"))
	}
	if requested.err == nil && !requested.deadline.IsZero() {
		return errors.Join(workErr, session.WriteWorkerEvent(out, session.WorkerEvent{Type: "DRAINED", Modules: modules, Clean: clean}))
	}
	reason := "WORKER_FAILED"
	if ctx.Err() != nil {
		reason = "WORKER_CANCELLED"
		workErr = errors.Join(workErr, ctx.Err())
	} else if requested.err != nil {
		reason = "SUPERVISOR_CONTROL_LOST"
		workErr = errors.Join(workErr, errors.New("portable supervisor control lost"))
	}
	return errors.Join(workErr, session.WriteWorkerEvent(out, session.WorkerEvent{Type: "FAILED", Modules: modules, Reason: reason}))
}

func reportWorkerFailure(out io.Writer, reason string) error {
	return session.WriteWorkerEvent(out, session.WorkerEvent{Type: "FAILED", Reason: reason})
}

func matchCapturedSecrets(config runtime.Config, secrets map[string]string) bool {
	count := 0
	for backend, c := range config.Backends {
		for name := range c.SecretSources {
			if _, err := hostSecret(secrets, backend+":"+name); err != nil {
				return false
			}
			count++
		}
	}
	return count == len(secrets)
}

type portableWork struct {
	config        runtime.Config
	manager       *runtime.Manager
	files         *upload.UploadStore
	backend       *discordbackend.Backend
	cancelBackend context.CancelFunc
}

func (w *portableWork) run(ctx context.Context, client *session.Client, secrets map[string]string, initialACL map[string]discordacl.Policy, acl <-chan session.WorkerACLChange, out io.Writer) error {
	startup, cancel := context.WithTimeout(ctx, time.Duration(w.config.Defaults.StartupDeadline))
	defer cancel()
	probe, finishProbe := context.WithTimeout(startup, time.Duration(w.config.Limits.HostOperationDeadline))
	err := client.Reconcile(probe)
	finishProbe()
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return errors.New("portable supervisor reconciliation failed")
	}
	w.files, err = upload.New(startup, upload.Config{ManagementDirectory: w.config.Host.ManagementDirectory, Limits: w.config.Limits, Portable: true})
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return errors.New("portable upload store initialization failed")
	}
	var registrations []runtime.BackendRegistration
	backendErrors := make(chan struct{}, 1)
	for id, config := range w.config.Backends {
		if id != "discord" || config.Major != 2 {
			return errors.New("unsupported portable worker backend")
		}
		var discord discordOperatorConfig
		if strictJSON(config.Config, &discord) != nil {
			return errors.New("invalid Discord operator configuration")
		}
		backendLife, cancelBackend := context.WithCancel(context.Background())
		w.cancelBackend = cancelBackend
		w.backend, err = newDiscordBackend(backendLife, w.config, config, &discord, w.files, secrets, func(error) {
			select {
			case backendErrors <- struct{}{}:
			default:
			}
		})
		if err != nil {
			return err
		}
		registrations = append(registrations, w.backend.Registration())
	}
	clear(secrets)
	var discordACL map[runtime.ModuleID]discordacl.Policy
	if len(initialACL) != 0 {
		discordACL = make(map[runtime.ModuleID]discordacl.Policy, len(initialACL))
		for id, policy := range initialACL {
			discordACL[runtime.ModuleID(id)] = policy
		}
	}
	w.manager, err = runtime.NewManager(w.config, runtime.ManagerOptions{Host: client, Backends: registrations,
		FileTransfer: w.files.RegistrarFactory, FileCleanup: w.files.CleanupInstance, DiscordACL: discordACL})
	if err != nil {
		return errors.New("portable runtime initialization failed")
	}
	if w.backend != nil {
		if w.backend.AttachDispatcher(w.manager.Dispatcher()) != nil || w.backend.Open(startup) != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("portable Discord backend startup failed")
		}
	}
	for _, spec := range w.config.Modules {
		if _, err = w.manager.Launch(startup, spec); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("portable module activation failed")
		}
	}
	cancel()
	if ctx.Err() != nil {
		return nil
	}
	previous := w.statuses(nil)
	if !allRunning(previous) {
		return errors.New("portable module exited during activation")
	}
	if err = session.WriteWorkerEvent(out, session.WorkerEvent{Type: "READY", Modules: previous}); err != nil {
		return err
	}
	var tick <-chan time.Time
	if len(previous) != 0 {
		ticker := time.NewTicker(time.Duration(w.config.Limits.ReadinessPollInterval))
		defer ticker.Stop()
		tick = ticker.C
	}
	next := make([]session.ModuleStatus, 0, len(previous))
	for {
		select {
		case <-ctx.Done():
			return nil
		case change := <-acl:
			// DRAIN cancels ctx directly from the frame reader, including while an
			// update is queued or waiting to enter the manager.
			if ctx.Err() != nil {
				return nil
			}
			apply, finishApply := context.WithTimeout(ctx, time.Duration(w.config.Limits.HostOperationDeadline))
			applyErr := w.manager.SetDiscordACL(apply, change.ModuleID, change.Policy)
			finishApply()
			if ctx.Err() != nil {
				return nil
			}
			status := session.WorkerACLApplied
			if applyErr != nil {
				status = session.WorkerACLRejected
			}
			if err = session.WriteWorkerEvent(out, session.WorkerEvent{Type: "ACL_ACK",
				ACL: &session.WorkerACLAck{Revision: change.Revision, Status: status}}); err != nil {
				return err
			}
		case <-backendErrors:
			if err = session.WriteWorkerEvent(out, session.WorkerEvent{Type: "STATUS", Modules: previous, Reason: "BACKEND_ERROR"}); err != nil {
				return err
			}
		case <-tick:
			next = w.statuses(next[:0])
			if !slices.Equal(previous, next) {
				if err = session.WriteWorkerEvent(out, session.WorkerEvent{Type: "STATUS", Modules: next}); err != nil {
					return err
				}
				previous, next = next, previous
			}
			if !anyRunning(previous) {
				return errors.New("all portable module instances exited")
			}
		}
	}
}

func (w *portableWork) close(deadline time.Time) bool {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	clean := true
	if w.manager != nil && len(w.config.Modules) != 0 {
		results := make(chan bool, len(w.config.Modules))
		for _, spec := range w.config.Modules {
			go func(id runtime.ModuleID) {
				err := w.manager.Stop(ctx, id)
				snapshot, exists := w.manager.ModuleSnapshot(id)
				results <- err == nil && (!exists || snapshot.CleanupComplete)
			}(spec.ModuleID)
		}
		for range w.config.Modules {
			if !<-results {
				clean = false
			}
		}
	}
	if w.backend != nil && w.backend.Close() != nil {
		clean = false
	}
	if w.cancelBackend != nil {
		w.cancelBackend()
	}
	if w.files != nil && w.files.Close(ctx) != nil {
		clean = false
	}
	return clean
}

func (w *portableWork) statuses(modules []session.ModuleStatus) []session.ModuleStatus {
	if modules == nil {
		modules = make([]session.ModuleStatus, 0, len(w.config.Modules))
	}
	for _, spec := range w.config.Modules {
		m := session.ModuleStatus{ModuleID: string(spec.ModuleID), State: "NOT_STARTED", CleanupComplete: true}
		if w.manager != nil {
			if s, exists := w.manager.ModuleSnapshot(spec.ModuleID); exists {
				m.InstanceID = string(s.Principal.InstanceID)
				m.State = stopState(s.State)
				m.Reason = stopFailureReason(s.FailureReason)
				m.CleanupComplete = s.CleanupComplete
			}
		}
		modules = append(modules, m)
	}
	return modules
}

func anyRunning(modules []session.ModuleStatus) bool {
	for _, m := range modules {
		if m.State == string(runtime.Running) {
			return true
		}
	}
	return false
}

func allRunning(modules []session.ModuleStatus) bool {
	for _, m := range modules {
		if m.State != string(runtime.Running) {
			return false
		}
	}
	return true
}
