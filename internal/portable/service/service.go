// Package service runs one foreground owner of a portable installation. The
// foreground process is the sole owner of module engines, not a system daemon.
package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/portable/engine"
	"github.com/thirdscam/chatanium/internal/portable/install"
	"github.com/thirdscam/chatanium/internal/portable/ipcpath"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/sandbox"
	"github.com/thirdscam/chatanium/internal/portable/session"
	"github.com/thirdscam/chatanium/internal/portable/store"
	"github.com/thirdscam/chatanium/internal/provision"
	modruntime "github.com/thirdscam/chatanium/internal/runtime"
)

// Run holds the installation lock through native child observation, lease
// settlement and control-channel shutdown. duration starts at worker READY.
// observe, if non-nil, receives lifecycle events synchronously; its errors
// are returned after cleanup.
func Run(ctx context.Context, dir, expectedID string, duration time.Duration, observe func(session.WorkerEvent) error, diagnostics io.Writer) (result error) {
	if duration < 0 {
		return errors.New("negative foreground duration")
	}
	i, err := install.Lock(dir)
	if err != nil {
		return err
	}
	defer i.Close()
	if i.Manifest.ID != expectedID {
		return store.ErrIdentity
	}
	if i.Manifest.Format != store.Format || i.Manifest.State != store.Ready {
		return errors.New("installation has not been activated")
	}
	if err = i.VerifyBundle(ctx); err != nil {
		return err
	}
	db, err := i.Store(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	record, err := db.Installation(ctx)
	if err != nil {
		return err
	}
	if record.State != store.Ready || record.PlanDigest != i.Manifest.PlanDigest || record.ConfigRevision != i.Manifest.Revision {
		return store.ErrApprovalMismatch
	}
	var configBytes bytes.Buffer
	if err = json.Compact(&configBytes, i.Manifest.Config); err != nil || provision.Digest(configBytes.Bytes()) != record.ConfigDigest {
		return store.ErrApprovalMismatch
	}
	cfg, err := modruntime.DecodeConfig(i.Manifest.Config)
	if err != nil {
		return err
	}
	modules, err := reviewedModules(cfg, i.Manifest)
	if err != nil {
		return err
	}
	program := func(id bundle.ProgramID) (string, error) {
		file, err := i.Manifest.Bundle.Program(id)
		if err != nil {
			return "", err
		}
		path, err := filepath.Localize(file.Path)
		if err != nil || !filepath.IsLocal(i.Manifest.CodeDir) {
			return "", errors.New("invalid installed program path")
		}
		return filepath.Join(i.Path, i.Manifest.CodeDir, path), nil
	}
	worker, err := program(bundle.Worker)
	if err != nil {
		return err
	}
	rungv, err := program(bundle.Rungv)
	if err != nil {
		return err
	}
	bridge, err := program(bundle.GuestBridge)
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	secrets, err := i.Secrets()
	if err != nil {
		return err
	}
	boot, err := process.BootIdentity()
	if err != nil {
		return err
	}
	identity, err := process.SelfIdentity()
	if err != nil {
		return err
	}
	epoch, err := db.BeginEpoch(ctx, store.EpochIdentity{BootID: boot, PID: os.Getpid(), StartIdentity: identity})
	if err != nil {
		return err
	}
	cleanupTime := time.Duration(cfg.Limits.TerminationDeadline) + time.Duration(cfg.Limits.HostOperationDeadline)
	var stop *stopServer
	var controlDir string
	var workerClaimed, workerObserved, ownsDir bool
	var cleanupErr error
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), cleanupTime)
		defer cancel()
		var fileErr error
		if stop != nil {
			fileErr = stop.listener.Close()
		}
		if ownsDir && workerObserved {
			fileErr = errors.Join(fileErr, ipcpath.RemoveWorkerDirectory(controlDir))
		}
		cleanupErr = errors.Join(cleanupErr, fileErr)
		if workerClaimed {
			if workerObserved && fileErr == nil {
				cleanupErr = errors.Join(cleanupErr, db.FinishWorker(c, epoch.ID))
			} else {
				cleanupErr = errors.Join(cleanupErr, process.ErrUnobserved)
			}
		}
		if cleanupErr == nil {
			cleanupErr = db.EndEpoch(c, epoch.ID)
		}
		if stop != nil {
			stop.close(cleanupErr == nil)
		}
		result = errors.Join(result, cleanupErr)
	}()
	controlDir, err = ipcpath.Directory(i.Path, epoch.ID)
	if err != nil {
		return err
	}
	if err = i.RecoverWorkers(ctx, db, epoch.ID); err != nil {
		return err
	}
	backend, err := sandbox.New(sandbox.Options{
		Store: db, Root: i.Root, OwnerLock: i.OwnerLock, InstallationID: i.Manifest.ID, Epoch: epoch.ID,
		ConfigRevision: record.ConfigRevision, SupervisorExecutable: self, EnginePath: rungv, BridgePath: bridge,
		Target:  engine.Target{OS: runtime.GOOS, Arch: runtime.GOARCH, HostCPUs: runtime.NumCPU()},
		Modules: modules, StartupTimeout: time.Duration(cfg.Defaults.StartupDeadline), CleanupTimeout: cleanupTime,
		Diagnostics: diagnostics,
	})
	if err != nil {
		return err
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), cleanupTime)
		defer cancel()
		cleanupErr = errors.Join(cleanupErr, backend.Close(c))
	}()
	if err = backend.Reconcile(ctx); err != nil {
		return err
	}
	if err = db.StartWorker(ctx, epoch.ID); err != nil {
		return err
	}
	workerClaimed, workerObserved = true, true // No native spawn yet.
	if err = os.Mkdir(controlDir, 0700); err != nil {
		if errors.Is(err, os.ErrExist) {
			workerObserved = false
		}
		return err
	}
	ownsDir = true
	if err = process.ProtectPrivateDir(controlDir); err != nil {
		return err
	}
	stop, err = listenStop(filepath.Join(controlDir, "stop"))
	if err != nil {
		return err
	}
	endpoint := filepath.Join(controlDir, "worker")
	creds, err := session.NewCredentials(epoch.ID)
	if err != nil {
		return err
	}
	listener, err := process.Listen(endpoint)
	if err != nil {
		return err
	}
	life, cancelServe := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	var serveErr error
	go func() { defer close(serveDone); serveErr = session.Serve(life, listener, creds, backend) }()
	defer func() { cancelServe(); <-serveDone; cleanupErr = errors.Join(cleanupErr, serveErr) }()
	result, workerObserved = runWorker(ctx, workerLaunch{
		self: self, program: worker, dir: i.Path, lock: i.OwnerLock,
		init: session.WorkerInit{Config: i.Manifest.Config, Credentials: creds, Endpoint: endpoint, Secrets: secrets},
		stop: stop.request, serveDone: serveDone, startup: time.Duration(cfg.Defaults.StartupDeadline),
		drain: time.Duration(cfg.Defaults.DrainDeadline) + cleanupTime, cleanup: cleanupTime,
		duration: duration, moduleCount: len(modules), observe: observe, fence: func(c context.Context) error { return db.RequestStop(c, epoch.ID) },
	})
	return result
}

func reviewedModules(cfg modruntime.Config, m install.Manifest) ([]sandbox.Module, error) {
	if len(cfg.Modules) != len(m.Modules) {
		return nil, store.ErrApprovalMismatch
	}
	if len(cfg.Modules) == 0 {
		return nil, nil
	}
	byID := make(map[string]*install.Module, len(m.Modules))
	for j := range m.Modules {
		v := &m.Modules[j]
		if _, ok := byID[v.ID]; ok {
			return nil, store.ErrApprovalMismatch
		}
		byID[v.ID] = v
	}
	out := make([]sandbox.Module, 0, len(cfg.Modules))
	for _, spec := range cfg.Modules {
		v := byID[string(spec.ModuleID)]
		if v == nil {
			return nil, store.ErrApprovalMismatch
		}
		review, err := v.Generation.ReviewDigest(json.RawMessage(v.ReviewJSON))
		if err != nil || review != v.Approval.ReviewDigest {
			return nil, fmt.Errorf("%w: module %s", store.ErrApprovalMismatch, spec.ModuleID)
		}
		launch, err := modruntime.ApprovedPortableLaunchPolicy(cfg, spec, v.Generation.Declaration)
		if err != nil {
			return nil, err
		}
		out = append(out, sandbox.Module{Spec: launch, Image: v.Generation, Approval: v.Approval})
		delete(byID, v.ID)
	}
	return out, nil
}
