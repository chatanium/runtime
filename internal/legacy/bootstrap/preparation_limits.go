package bootstrap

import (
	"errors"
	"github.com/thirdscam/chatanium/internal/legacy/host"
	"github.com/thirdscam/chatanium/internal/provision"
)

// FitPreparationLimits derives defaults with four retained-image slots in the
// total source/cache pools; explicit approved limits are never resized.
func FitPreparationLimits(base provision.PrepareLimits, total, available host.StorageBudget) (provision.PrepareLimits, error) {
	const block int64 = 4096
	down := func(value int64) int64 { return value / block * block }
	base.InputBytes = down(min(base.InputBytes, total.SourceBytes/8, available.SourceBytes/2))
	base.ExpandedBytes = down(min(base.ExpandedBytes, available.PreparationBytes/2))
	base.OutputBytes = down(min(base.OutputBytes, total.CacheBytes/4, available.CacheBytes, available.PreparationBytes-base.ExpandedBytes))
	base.Inodes = min(base.Inodes, total.SourceInodes/4, total.CacheInodes/4, available.SourceInodes, available.CacheInodes, available.PreparationInodes)
	if e := base.Validate(); e != nil {
		return base, errors.New("remaining preparation claims cannot fit positive finite source/cache/work peaks")
	}
	return base, nil
}
