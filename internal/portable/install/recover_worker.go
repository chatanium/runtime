package install

import (
	"context"
	"errors"
	"fmt"

	"github.com/thirdscam/chatanium/internal/portable/ipcpath"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

// RecoverWorkers can release an old native worker intent after a different OS
// boot. On the same boot neither a missing PID nor an unlocked file proves exit.
func (i *Installation) RecoverWorkers(ctx context.Context, db *store.Store, epochID string) error {
	if i.OwnerLock == nil {
		return errors.New("worker reconciliation requires the installation owner lock")
	}
	now, err := db.Epoch(ctx, epochID)
	if err != nil {
		return err
	}
	workers, err := db.WorkerEpochs(ctx)
	if err != nil {
		return err
	}
	for _, old := range workers {
		if old.BootID == "" || old.BootID == now.BootID {
			return fmt.Errorf("%w: %w (worker epoch %s)", store.ErrCleanupPending, process.ErrUnobserved, old.ID)
		}
		leaf, err := ipcpath.Directory(i.Path, old.ID)
		if err != nil {
			return err
		}
		if err = ipcpath.RemoveWorkerDirectory(leaf); err != nil {
			return err
		}
		if err = db.RecoverWorker(ctx, now.ID, old.ID, store.RemovalProof{WritersExited: true, FilesAbsent: true}); err != nil {
			return err
		}
	}
	return nil
}
