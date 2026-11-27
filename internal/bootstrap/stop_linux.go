//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/runtime"
	"golang.org/x/sys/unix"
	"math"
	"time"
)

func cleanupTimeout(config runtime.Config) (time.Duration, error) {
	var total time.Duration
	for _, value := range []time.Duration{time.Duration(config.Defaults.DrainDeadline), time.Duration(config.Limits.TerminationDeadline), time.Duration(config.Limits.HostOperationDeadline)} {
		if value <= 0 || value > time.Duration(math.MaxInt64)-total {
			return 0, errors.New("invalid or overflowing cleanup budget")
		}
		total += value
	}
	return total, nil
}
func waitOwnerRelease(ctx context.Context, id RuntimeInstallationID) error {
	store, m, e := openInstallation(ctx, id)
	if e != nil {
		return e
	}
	defer store.Close()
	revision := m.ActiveRevision
	if revision == "" {
		revision = m.PendingRevision
	}
	budget := time.Minute
	if revision != "" {
		record, e := store.Revision(ctx, revision)
		if e != nil {
			return e
		}
		config, e := runtime.DecodeConfig(record.Config)
		if e != nil {
			return e
		}
		budget, e = cleanupTimeout(config)
		if e != nil {
			return e
		}
	}
	if e = store.Close(); e != nil {
		return e
	}
	bounded, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	for {
		current, _, e := openInstallation(bounded, id)
		if e != nil {
			return e
		}
		lease, e := current.AcquireLease(bounded)
		if e == nil {
			return errors.Join(lease.Close(), current.Close())
		}
		if closeErr := current.Close(); closeErr != nil {
			return errors.Join(e, closeErr)
		}
		if !errors.Is(e, unix.EWOULDBLOCK) && !errors.Is(e, unix.EAGAIN) {
			return e
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-bounded.Done():
			timer.Stop()
			return bounded.Err()
		case <-timer.C:
		}
	}
}
