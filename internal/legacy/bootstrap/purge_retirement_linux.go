//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/legacy/host"
	"os"
	"path/filepath"
	"strings"
)

func releasePurgeReferences(ctx context.Context, s *ownedSession, selected []host.ProvisionRecord, removeBacking bool) ([]string, error) {
	paths := map[string]bool{}
	control := false
	for _, record := range selected {
		paths[record.Identity] = true
		control = control || record.Identity == s.manifest.Paths.Control
	}
	var intents []string
	s.purgeRetirements = make(map[string]bool)
	for _, record := range selected {
		selectedGeneration := record.Kind == "backing" || record.Kind == "bundle"
		if record.Kind == "bundle" && !control {
			var p host.ProvisionProperties
			if e := gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
				return nil, e
			}
			if p.Digest == s.manifest.BundleDigest {
				return nil, errors.New("active helper bundle must remain until final state purge")
			}
		}
		base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(record.Identity, ".json"), ".sqlite"), ".xfs")
		backup := filepath.Dir(base) == s.manifest.Paths.Installation && strings.HasPrefix(filepath.Base(base), "backup-")
		if backup {
			if !paths[base+".json"] || !paths[base+".sqlite"] || !paths[base+".xfs"] {
				return nil, errors.New("backup retirement requires its exact manifest/journal/backing triple")
			}
			selectedGeneration = true
		}
		if !selectedGeneration {
			continue
		}
		intent, e := beginRemoval(ctx, s.store, record)
		if e != nil {
			return nil, e
		}
		intents = append(intents, intent)
		s.purgeRetirements[record.ID] = true
	}
	if len(intents) > 0 {
		if e := s.store.RetirePurgeGenerations(ctx, intents, s.cleanupEvidence); e != nil {
			return nil, e
		}
	}
	return intents, nil
}
func completePurgeRetirement(ctx context.Context, s *ownedSession, intents []string, removedBacking bool) error {
	if len(intents) == 0 {
		return nil
	}
	proof, e := s.systemd.SettleHelpers(ctx)
	if e != nil {
		return e
	}
	var storage host.CleanupEvidence
	if removedBacking {
		storage, e = host.VerifyRemovedBacking(ctx, s.manifest, s.store)
	} else {
		storage, e = host.VerifyDetached(ctx, s.manifest)
		storage.QuotaReclaimed = s.cleanupEvidence.QuotaReclaimed
	}
	if e != nil {
		return e
	}
	if proof.BootID != storage.BootID {
		return errors.New("purge cleanup boot fence changed")
	}
	proof.MountsAbsent = storage.MountsAbsent
	proof.OpenReferencesAbsent = proof.OpenReferencesAbsent && storage.OpenReferencesAbsent
	proof.QuotaReclaimed = storage.QuotaReclaimed
	return s.store.CompletePurgeRetirement(ctx, intents, proof)
}
func removedPath(path string) bool { _, e := os.Lstat(path); return os.IsNotExist(e) }
