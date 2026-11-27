//go:build linux

package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/thirdscam/chatanium/internal/bootstrap"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
)

// workerRun owns the only worker-control writer. Observations never bypass its
// envelope and no backend reads ambient process credentials.
type workerRun struct {
	mu           sync.Mutex
	outputMu     sync.Mutex
	output       io.Writer
	observations io.Writer
	secrets      map[string]string
	operationID  string
	deadline     time.Time
	terminal     bool
	cleanup      bootstrap.WorkerDrainResult
}

type workerObservationWriter struct{ run *workerRun }

func (w workerObservationWriter) Write(raw []byte) (int, error) {
	if len(raw) > bootstrap.WorkerObservationMaxBytes {
		return 0, errors.New("worker observation exceeds bound")
	}
	if err := w.run.event(bootstrap.WorkerEvent{Version: 1, Type: "OBSERVATION", Observation: json.RawMessage(raw)}); err != nil {
		return 0, err
	}
	return len(raw), nil
}
func (w *workerRun) event(event bootstrap.WorkerEvent) error {
	w.outputMu.Lock()
	defer w.outputMu.Unlock()
	if w.terminal {
		return errors.New("worker control already terminal")
	}
	if event.Type == "DRAINED" || event.Type == "FAILED" {
		w.terminal = true
	}
	return bootstrap.WriteWorkerEvent(w.output, event)
}
func (w *workerRun) ready() error             { return w.event(bootstrap.WorkerEvent{Version: 1, Type: "READY"}) }
func (w *workerRun) drainDeadline() time.Time { w.mu.Lock(); defer w.mu.Unlock(); return w.deadline }
func (w *workerRun) recordCleanup(manager *runtime.Manager, specs []runtime.ModuleSpec, failures []error) {
	result := bootstrap.WorkerDrainResult{Modules: make([]bootstrap.WorkerModuleCleanup, 0, len(specs))}
	for _, spec := range specs {
		entry := bootstrap.WorkerModuleCleanup{ModuleID: string(spec.ModuleID), CleanupComplete: true}
		if manager != nil {
			if instance, ok := manager.Instance(spec.ModuleID); ok {
				snapshot := instance.Snapshot()
				entry.InstanceID = string(snapshot.Principal.InstanceID)
				entry.FailureReason = snapshot.FailureReason
				entry.CleanupComplete = snapshot.CleanupComplete
				for _, phase := range runtime.CleanupFailurePhases(snapshot.CleanupError) {
					entry.CleanupErrors = append(entry.CleanupErrors, bootstrap.OperationFailure{Phase: phase.String(), Code: "CLEANUP_INCOMPLETE", Message: "module cleanup step failed"})
				}
			}
		}
		result.Modules = append(result.Modules, entry)
	}
	for range failures {
		result.Failures = append(result.Failures, bootstrap.OperationFailure{Phase: "worker", Code: "CLEANUP_INCOMPLETE", Message: "worker resource cleanup failed"})
	}
	w.mu.Lock()
	w.cleanup = result
	w.mu.Unlock()
}

// runLegacyWorker consumes only the root owner's private, bounded initialization.
// The input must be closeable so every return can join the blocked read loop.
func runLegacyWorker(ctx context.Context, input io.Reader, output io.Writer, diagnostics io.Writer) (result error) {
	pipe, ok := input.(io.Closer)
	if !ok {
		return errors.New("worker control input must be closeable")
	}
	outputPipe, ok := output.(io.Closer)
	if !ok {
		return errors.New("worker control output must be closeable")
	}
	stopInput := context.AfterFunc(ctx, func() { _ = pipe.Close() })
	defer stopInput()
	control := &workerRun{output: output}
	watchdogDone := make(chan struct{})
	watchdogExited := make(chan struct{})
	watchdogStarted := false
	defer func() {
		defer func() {
			close(watchdogDone)
			if watchdogStarted {
				<-watchdogExited
			}
		}()
		if result == nil {
			return
		}
		control.outputMu.Lock()
		terminal := control.terminal
		control.outputMu.Unlock()
		if terminal {
			return
		}
		control.mu.Lock()
		operation := control.operationID
		control.mu.Unlock()
		result = errors.Join(result, control.event(bootstrap.WorkerEvent{Version: 1, Type: "FAILED", OperationID: operation, Failure: &bootstrap.OperationFailure{Phase: "worker", Code: "WORKER_FAILED", Message: "worker startup or lifecycle failed"}}))
	}()
	first, err := bootstrap.ReadWorkerCommand(input)
	if err != nil || first.Type != "INIT" {
		return errors.New("worker requires one initialization packet")
	}
	init := first.Init
	if err = bootstrap.ValidateWorkerInit(*init); err != nil {
		return err
	}
	if init.Options.DevelopmentRevision != "" && (!init.Options.DevelopmentMode || init.Revision != init.Options.DevelopmentRevision) {
		return errors.New("worker development revision binding mismatch")
	}
	config, err := runtime.DecodeConfig(init.Config)
	if err != nil {
		return err
	}
	if config.Host.Format != "" {
		return errors.New("legacy worker requires its original installation format")
	}
	options := workerOptions(init.Options)
	if err = validateDevelopmentOptions(options); err != nil {
		return err
	}
	if options.DevelopmentMode {
		if err := config.Host.ValidateDevelopmentSocket(options.DevelopmentSocket); err != nil {
			return err
		}
	}
	if err = applyDevelopmentImages(&config, options.DevelopmentImages); err != nil {
		return err
	}
	if len(config.Modules) == 0 {
		return errors.New("worker requires installed modules")
	}
	if int64(config.Defaults.DrainDeadline) > int64(^uint64(0)>>1)-int64(config.Limits.TerminationDeadline) {
		return errors.New("worker shutdown deadline overflows")
	}
	expected := make(map[string]bool)
	for id, backend := range config.Backends {
		for name := range backend.SecretSources {
			expected[id+":"+name] = true
		}
	}
	if len(expected) != len(init.Secrets) {
		return errors.New("worker secret bindings differ from approved configuration")
	}
	for name := range expected {
		if _, ok := init.Secrets[name]; !ok {
			return errors.New("worker secret binding unavailable")
		}
	}
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	if options.Duration > 0 {
		var stop context.CancelFunc
		life, stop = context.WithTimeout(life, options.Duration)
		defer stop()
	}
	control.secrets = init.Secrets
	control.observations = workerObservationWriter{control}
	control.recordCleanup(nil, config.Modules, nil)
	watchdogStarted = true
	go func() {
		defer close(watchdogExited)
		select {
		case <-watchdogDone:
			return
		case <-life.Done():
		}
		deadline := control.drainDeadline()
		if deadline.IsZero() {
			deadline = time.Now().Add(time.Duration(config.Defaults.DrainDeadline) + time.Duration(config.Limits.TerminationDeadline))
		}
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case <-watchdogDone:
			return
		case <-timer.C:
			_ = outputPipe.Close()
			_ = pipe.Close()
		}
	}()
	readDone := make(chan struct{})
	var protocolErr error
	go func() {
		defer close(readDone)
		for {
			command, readErr := bootstrap.ReadWorkerCommand(input)
			if readErr != nil {
				if !errors.Is(readErr, io.EOF) && life.Err() == nil {
					protocolErr = errors.New("worker control read failed")
				}
				cancel()
				return
			}
			control.mu.Lock()
			if command.Type != "DRAIN" || control.operationID != "" {
				control.mu.Unlock()
				protocolErr = errors.New("invalid repeated worker command")
				cancel()
				return
			}
			remaining := time.Duration(command.RemainingNS)
			maximum := time.Duration(config.Defaults.DrainDeadline) + time.Duration(config.Limits.TerminationDeadline)
			if remaining > maximum {
				remaining = maximum
			}
			control.operationID = command.OperationID
			control.deadline = time.Now().Add(remaining)
			control.mu.Unlock()
			cancel()
		}
	}()
	err = serve(life, config, init.Host, options, control)
	cancel()
	_ = pipe.Close()
	<-readDone
	control.mu.Lock()
	operation := control.operationID
	drain := control.cleanup
	control.mu.Unlock()
	if protocolErr != nil {
		err = errors.Join(err, protocolErr)
	}
	if operation != "" && protocolErr == nil {
		return errors.Join(err, control.event(bootstrap.WorkerEvent{Version: 1, Type: "DRAINED", OperationID: operation, Drain: &drain}))
	}
	return err
}
