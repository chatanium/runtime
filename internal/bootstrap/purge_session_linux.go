//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"os"
)

func acquirePurgeSession(ctx context.Context, id RuntimeInstallationID, scope []ApprovedObject) (*ownedSession, []ObjectResult, []ApprovedObject, error) {
	store, m, e := openInstallation(ctx, id)
	if e != nil {
		return nil, nil, nil, e
	}
	store.Close()
	_, statErr := os.Lstat(m.Paths.BackingFile)
	if m.ActiveRevision == "" || os.IsNotExist(statErr) {
		s, e := openPurgeOwner(ctx, id)
		if e != nil {
			return nil, nil, nil, e
		}
		if s.manifest.ActiveRevision == "" {
			report, e := cleanupProvisioning(ctx, s)
			if e != nil || !report.Complete {
				closeMaintenance(s)
				return nil, nil, nil, errors.Join(e, host.ErrCleanupIncomplete)
			}
			return s, nil, scope, nil
		}
		if e = reconcilePurgeNetwork(ctx, s); e != nil {
			closeMaintenance(s)
			return nil, nil, nil, e
		}
		storage, e := host.VerifyRemovedBacking(ctx, s.manifest, s.store)
		if e != nil {
			closeMaintenance(s)
			return nil, nil, nil, e
		}
		proof := s.cleanupEvidence
		proof.MountsAbsent = storage.MountsAbsent
		proof.OpenReferencesAbsent = proof.OpenReferencesAbsent && storage.OpenReferencesAbsent
		proof.QuotaReclaimed = storage.QuotaReclaimed
		s.cleanupEvidence = proof
		if !proof.JobsAbsent || !proof.ProcessesAbsent || !proof.TransportsClosed || !proof.OpenReferencesAbsent || !proof.MountsAbsent || !proof.QuotaReclaimed {
			closeMaintenance(s)
			return nil, nil, nil, host.ErrCleanupIncomplete
		}
		if e = s.store.SetDesired(ctx, "STOPPED", newID()); e != nil {
			closeMaintenance(s)
			return nil, nil, nil, e
		}
		s.manifest.DesiredRunState = "STOPPED"
		return s, nil, scope, nil
	}
	if statErr != nil {
		return nil, nil, nil, statErr
	}
	s, e := acquirePurgeRuntime(ctx, id)
	if e != nil {
		return nil, nil, nil, e
	}
	removed, remaining, e := s.purgeDevelopment(ctx, scope)
	if e != nil {
		_, cleanup := DrainOwnedSession(context.Background(), OwnedSession{s})
		closeMaintenance(s)
		return nil, removed, scope, errors.Join(e, cleanup)
	}
	report, e := DrainOwnedSession(ctx, OwnedSession{s})
	if e != nil || !report.Complete {
		closeMaintenance(s)
		return nil, removed, remaining, errors.Join(e, host.ErrCleanupIncomplete)
	}
	if e = s.supervisor.Close(); e != nil {
		closeMaintenance(s)
		return nil, removed, remaining, e
	}
	s.supervisor = nil
	s.manifest, e = s.store.Installation(ctx)
	if e != nil {
		closeMaintenance(s)
		return nil, removed, remaining, e
	}
	return s, removed, remaining, nil
}
func removalFor(ctx context.Context, store *host.Store, original host.ProvisionRecord) (host.ProvisionRecord, bool, error) {
	records, e := store.ObjectProvisions(ctx, original.Kind, original.Identity)
	if e != nil {
		return host.ProvisionRecord{}, false, e
	}
	for _, record := range records {
		if !record.ExistedBefore || record.ProductCreated {
			continue
		}
		var p host.ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &p); e != nil {
			return host.ProvisionRecord{}, false, e
		}
		if p.Source == "remove" && p.Revision == original.ID {
			return record, true, nil
		}
	}
	return host.ProvisionRecord{}, false, nil
}
func purgeRecords(ctx context.Context, store *host.Store, scope []ApprovedObject) ([]host.ProvisionRecord, error) {
	pending, e := store.PendingProvisions(ctx)
	if e != nil {
		return nil, e
	}
	records := make([]host.ProvisionRecord, 0, len(pending))
	seen := map[string]bool{}
	for _, record := range pending {
		if record.ExistedBefore && !record.ProductCreated {
			var p host.ProvisionProperties
			if e = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &p); e != nil {
				return nil, e
			}
			if p.Source == "remove" {
				original, e := store.Provision(ctx, p.Revision)
				if e != nil {
					return nil, e
				}
				if !seen[original.ID] {
					records = append(records, original)
					seen[original.ID] = true
				}
				continue
			}
		}
		if !seen[record.ID] {
			records = append(records, record)
			seen[record.ID] = true
		}
	}
	for _, approval := range scope {
		history, e := store.ObjectProvisions(ctx, approval.Kind, approval.Identity)
		if e != nil {
			return nil, e
		}
		for _, record := range history {
			if !record.ProductCreated || record.ExistedBefore || record.State != "OBSERVED" || seen[record.ID] {
				continue
			}
			sum, e := ObjectObservationDigest(record.Observed)
			if e != nil {
				return nil, e
			}
			if sum != approval.ObservationDigest {
				continue
			}
			if _, exists, e := removalFor(ctx, store, record); e != nil {
				return nil, e
			} else if exists {
				records = append(records, record)
				seen[record.ID] = true
			}
		}
	}
	return records, nil
}
func authorizePurgeRecord(ctx context.Context, store *host.Store, record host.ProvisionRecord, approval ApprovedObject) error {
	copy := record
	if record.CleanupState == "COMPLETE" {
		if e := completedObjectAbsent(record); e != nil {
			return e
		}
		if _, exists, e := removalFor(ctx, store, record); e != nil {
			return e
		} else if !exists {
			return errors.New("completed object has no approved removal lineage")
		}
		copy.CleanupState = "PENDING"
	}
	return authorizeRemoval(copy, approval)
}
func matchPurgeRecord(ctx context.Context, store *host.Store, record host.ProvisionRecord) error {
	if absent, e := bootEphemeralAbsent(ctx, store, record); absent || e != nil {
		return e
	}
	if complete, e := rejectCompletedReappearance(ctx, store, record); complete || e != nil {
		return e
	}
	e := matchRecord(record)
	if e == nil {
		return nil
	}
	_, removing, lookup := removalFor(ctx, store, record)
	if lookup != nil {
		return lookup
	}
	if !removing {
		return e
	}
	var p host.ProvisionProperties
	if lookup = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); lookup != nil {
		return lookup
	}
	path := record.Identity
	if record.Kind == "bundle" {
		path = p.Path
	}
	if record.Kind == "account" {
		return accountRemovalState(p)
	}
	if record.Kind == "bundle" && bundleRemovalRootMatches(path, p) {
		return nil
	}
	if _, statErr := os.Lstat(path); os.IsNotExist(statErr) {
		return trustedPathParent(path)
	}
	return e
}
func trustedPathParent(path string) error {
	parent := path
	for {
		index := -1
		for i := len(parent) - 1; i >= 0; i-- {
			if parent[i] == '/' {
				index = i
				break
			}
		}
		if index < 1 {
			parent = "/"
		} else {
			parent = parent[:index]
		}
		if parent == "/" {
			return nil
		}
		if _, e := os.Lstat(parent); e == nil {
			return trustedPath(parent, false)
		} else if !os.IsNotExist(e) {
			return e
		}
	}
}
