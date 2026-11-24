// Package preparehost connects the trusted image preparer to a managed GVX
// child. Prepare must not send external input until this callback returns.
package preparehost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/thirdscam/chatanium/internal/portable/engine"
	"github.com/thirdscam/chatanium/internal/portable/images"
	"github.com/thirdscam/chatanium/internal/portable/ipcpath"
	"github.com/thirdscam/chatanium/internal/portable/process"
)

// Managed binds the installation's lifetime lock to every compiler guardian.
func Managed(lock *process.OwnerLock) func(context.Context, images.PreparationLaunch) (images.PreparationProcess, error) {
	return func(ctx context.Context, launch images.PreparationLaunch) (images.PreparationProcess, error) {
		if lock == nil || launch.Limits.NanoCPUs <= 0 || launch.Limits.NanoCPUs%1_000_000 != 0 || launch.Stdin == nil || launch.Stdout == nil || launch.Stderr == nil {
			return nil, errors.New("invalid managed preparation resources")
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ctrlDir, err := ipcpath.Directory(launch.Directory, "prepare:"+launch.Epoch+":"+launch.JobID)
		if err != nil {
			return nil, err
		}
		if err := os.Mkdir(ctrlDir, 0700); err != nil {
			return nil, err
		}
		if err := process.ProtectPrivateDir(ctrlDir); err != nil {
			return nil, errors.Join(err, os.Remove(ctrlDir))
		}
		e := engine.Endpoint{SocketPath: filepath.Join(ctrlDir, "control"), TokenPath: filepath.Join(ctrlDir, "token")}
		remove := func() error { return RemoveEndpoint(launch.Directory, launch.Epoch, launch.JobID) }
		resources := engine.ResourceLimits{CPUMillicores: launch.Limits.NanoCPUs / 1_000_000, MemoryBytes: launch.Limits.MemoryBytes, MaxPIDs: launch.Limits.Tasks}
		identity := engine.InstanceIdentity{InstallationID: launch.InstallationID, EpochID: launch.Epoch, InstanceID: launch.JobID, ReviewDigest: launch.PlanDigest}
		plan, err := engine.PlanPreparation(engine.Target{OS: runtime.GOOS, Arch: runtime.GOARCH, HostCPUs: runtime.NumCPU()}, resources, engine.PreparationSpec{CacheDir: launch.CacheDir, HelperPath: launch.GuestPreparer, CompilerPath: launch.GuestCompiler, ScratchBytes: launch.ScratchBytes, Identity: identity, Endpoint: e})
		if err != nil {
			return nil, errors.Join(err, remove())
		}
		child, err := process.Start(launch.Supervisor, process.Spec{Path: launch.Engine, Args: plan.Args(), Dir: launch.Directory, Stdin: launch.Stdin, Stdout: launch.Stdout, Stderr: launch.Stderr, OwnerLock: lock})
		if err != nil {
			if errors.Is(err, process.ErrUnobserved) {
				return nil, err
			}
			return nil, errors.Join(err, remove())
		}
		adapter, err := engine.Connect(ctx, plan, engine.Peer{Done: child.Done(), Exited: child.Observed, Kill: child.Close})
		if err != nil {
			reap, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			stopErr := child.Stop(reap, nil)
			cancel()
			if !child.Observed() {
				return nil, errors.Join(err, stopErr, process.ErrUnobserved)
			}
			return nil, errors.Join(fmt.Errorf("attest isolated image preparer: %w", err), stopErr, remove())
		}
		return &managedPreparer{child: child, control: adapter, remove: remove}, nil
	}
}

// RemoveEndpoint requires complete writer-exit evidence. The token and socket
// may live outside the job directory to satisfy the AF_UNIX path bound.
func RemoveEndpoint(job, epoch, id string) error {
	dir, err := ipcpath.Directory(job, "prepare:"+epoch+":"+id)
	if err != nil {
		return errors.Join(err, process.ErrUnobserved)
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.Join(err, process.ErrUnobserved)
	}
	if err := process.CheckPrivateDir(dir); err != nil {
		return errors.Join(err, process.ErrUnobserved)
	}
	for _, name := range []string{"control", "token"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.Join(err, process.ErrUnobserved)
		}
	}
	if err := os.Remove(dir); err != nil {
		return errors.Join(err, process.ErrUnobserved)
	}
	return nil
}

type managedPreparer struct {
	child   *process.Child
	control *engine.GVXAdapter
	remove  func() error
	once    sync.Once
	cleanup error
}

func (p *managedPreparer) finish(err error) error {
	if !p.child.Observed() {
		return errors.Join(err, process.ErrUnobserved)
	}
	p.once.Do(func() { p.cleanup = errors.Join(p.control.Close(), p.remove()) })
	return errors.Join(err, p.cleanup)
}
func (p *managedPreparer) Wait() error { return p.finish(p.child.Wait()) }
func (p *managedPreparer) Stop(ctx context.Context, graceful func(context.Context) error) error {
	if graceful == nil {
		graceful = func(c context.Context) error { return p.control.Stop(c, time.Second) }
	}
	return p.finish(p.child.Stop(ctx, graceful))
}
