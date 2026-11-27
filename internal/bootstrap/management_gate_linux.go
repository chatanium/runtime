//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/host"
)

// An exclusive terminal transaction borrows its one continuous global guard.
// Ordinary callers transfer a newly acquired shared guard into the store/reader.
func acquireManagementGuard(ctx context.Context) (*host.ManagementGuard, error) {
	guard, e := host.ManagementGuardFromContext(ctx)
	if e == nil {
		if !guard.Live() || guard.Mode() != host.ManagementExclusive {
			return nil, errors.New("management context does not hold a live exclusive guard")
		}
		return guard, nil
	}
	if !errors.Is(e, host.ErrManagementGuardAbsent) {
		return nil, e
	}
	return host.AcquireManagementGuard(ctx, host.ManagementShared)
}
func closeUnadoptedManagementGuard(guard *host.ManagementGuard) {
	if guard != nil && guard.Mode() == host.ManagementShared {
		guard.Close()
	}
}
