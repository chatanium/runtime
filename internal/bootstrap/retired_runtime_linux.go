//go:build linux

package bootstrap

import (
	"context"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"path/filepath"
	"strings"
)

func preflightRetiredRuntime(ctx context.Context, id RuntimeInstallationID) error {
	metadata, e := openMetadata(ctx, id)
	if e != nil {
		return e
	}
	defer metadata.Close()
	m, e := metadata.Installation(ctx)
	if e != nil {
		return e
	}
	for _, target := range []struct{ kind, path string }{{"backing", m.Paths.BackingFile}, {"bundle", m.Paths.EngineRoot}, {"bundle", filepath.Join(m.Paths.EngineRoot, strings.TrimPrefix(m.BundleDigest, "sha256:"))}} {
		records, e := metadata.ObjectProvisions(ctx, target.kind, target.path)
		if e != nil {
			return e
		}
		for _, original := range records {
			if original.State != "OBSERVED" || !original.ProductCreated || original.ExistedBefore {
				continue
			}
			for _, removal := range records {
				if !removal.ExistedBefore || removal.ProductCreated {
					continue
				}
				var p host.ProvisionProperties
				if e = gvxcontract.DecodeStrict(removal.Desired, 64<<10, 16, &p); e != nil {
					return e
				}
				if p.Source == "remove" && p.Revision == original.ID && (original.CleanupState == "COMPLETE" || removal.CleanupState == "COMPLETE") {
					if e = completedObjectAbsent(original); e != nil {
						return e
					}
				}
			}
		}
	}
	return nil
}
