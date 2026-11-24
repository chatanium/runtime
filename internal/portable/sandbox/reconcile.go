package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

// ObserveVolume verifies the installation-owned backing and its stable native
// identity. The caller must hold the installation's exclusive owner lock or
// already own the corresponding live run. An unrecognized backing is never
// opened by GVX or treated as a newly allocated volume.
func ObserveVolume(root *os.Root, volume store.Volume) (store.PersistentObservation, error) {
	path, err := localPath(volume.Path)
	if err != nil {
		return store.PersistentObservation{}, err
	}
	actual, err := observeVolume(root, path)
	if err != nil {
		return store.PersistentObservation{}, err
	}
	if err := validateVolume(volume, actual); err != nil {
		return store.PersistentObservation{}, err
	}
	return actual, nil
}

// ReconcileOffline settles previous runs under the installation owner's native
// lock. A new PID or lock holder alone never proves the former scope exited.
func ReconcileOffline(ctx context.Context, db *store.Store, root *os.Root, epochID string) error {
	epoch, err := db.Epoch(ctx, epochID)
	if err != nil {
		return err
	}
	boot, err := process.BootIdentity()
	if err != nil {
		return err
	}
	if epoch.BootID != boot {
		return store.ErrIdentity
	}
	runs, err := db.Runs(ctx)
	if err != nil {
		return err
	}
	var result error
	for _, run := range runs {
		result = errors.Join(result, reconcileRun(ctx, db, root, epoch, run))
	}
	return result
}

func reconcileRun(ctx context.Context, db *store.Store, root *os.Root, epoch store.Epoch, run store.Run) error {
	if !run.LaunchBegun {
		// No instance file or process operation precedes BeginLaunch.
		return db.CancelRun(ctx, epoch.ID, run.Key)
	}
	prior, err := db.Epoch(ctx, run.Key.EpochID)
	if err != nil || prior.BootID == "" || epoch.BootID == "" || prior.BootID == epoch.BootID || !run.CleanupPending {
		return errors.Join(fmt.Errorf("%w: native exit of instance %s is unconfirmed", store.ErrCleanupPending, run.InstanceID), err)
	}
	if err := releaseObserved(ctx, db, root, epoch.ID, run, nil); err != nil {
		return fmt.Errorf("%w: recover instance %s: %w", store.ErrCleanupPending, run.InstanceID, err)
	}
	return nil
}

func releaseObserved(ctx context.Context, db *store.Store, root *os.Root, epochID string, run store.Run, live *instance) error {
	if run.Persistent.Initialized {
		if _, err := ObserveVolume(root, run.Persistent); err != nil {
			return err
		}
	} else if err := reclaimPersistent(root, run, live); err != nil {
		return err
	}
	if err := removeRunFiles(root, run, live); err != nil {
		return err
	}
	return db.ReleaseRun(ctx, epochID, run.Key, store.RunCleanup{
		ChildrenExited: true, BackingClosed: true, TemporaryFilesAbsent: true,
		PersistentBackingAbsent: !run.Persistent.Initialized,
	})
}

// reclaimPersistent is called only after positive native writer exit. A
// failed startup may leave a short, unformatted, or partially initialized
// backing; the journal's uninitialized native identity, not the file bytes,
// is the proof of ownership. Never erase an unrecognized or retained image.
func reclaimPersistent(root *os.Root, run store.Run, live *instance) error {
	vol := run.Persistent
	path, err := localPath(vol.Path)
	if err != nil {
		return err
	}
	actual, err := observeVolume(root, path)
	if err != nil {
		return err
	}
	if actual.Exists {
		if vol.Initialized || vol.NativeID == "" || vol.NativeID != actual.NativeID || vol.CreationRunID != run.Key.ID {
			return errors.New("refusing to reclaim an unrecognized or retained persistent backing")
		}
		runPath, err := localPath(run.InstancePath)
		if err != nil {
			return err
		}
		if live != nil && !live.runDirOwned {
			return errors.New("provisional backing belongs to an unconfirmed run workspace")
		}
		if err := privateParents(root, runPath, false); err != nil {
			return err
		}
		// Use a durable move back into the run before releasing the creation
		// intent; this also handles Windows where directory fsync is absent.
		if err := moveExclusive(root, path, filepath.Join(runPath, reclaimLeaf)); err != nil {
			return fmt.Errorf("retire uninitialized persistent backing: %w", err)
		}
	}
	if _, err := root.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(err, errors.New("uninitialized persistent backing is still present"))
	}
	// A retry after an earlier move with a failed sync must make canonical
	// absence durable before forgetting the provisional identity.
	if vol.NativeID != "" {
		return syncPath(root, filepath.Dir(path))
	}
	return nil
}
