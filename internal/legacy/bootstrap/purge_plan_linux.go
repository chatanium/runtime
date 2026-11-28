//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/legacy/host"
	"path/filepath"
	"sort"
)

func PlanPurge(ctx context.Context, id RuntimeInstallationID) (PurgeApproval, error) {
	plan := PurgeApproval{PlanID: newID(), InstallationID: id}
	guard, e := host.AcquireManagementGuard(ctx, host.ManagementExclusive)
	if e != nil {
		return plan, e
	}
	defer guard.Close()
	ctx = host.WithManagementGuard(ctx, guard)
	if terminal, found, e := terminalApprovedPlan(ctx, guard, id); found || e != nil {
		return terminal, e
	}
	plan.ManagementAnchor, e = host.ObserveManagementAnchor(ctx)
	if e != nil {
		return plan, e
	}
	plan.TerminalReceiptPath = terminalReceiptPath(id)
	plan.PublicationProbePaths = [2]string{filepath.Join(terminalRoot, terminalStageName(id, plan.PlanID, 0)), filepath.Join(terminalRoot, terminalStageName(id, plan.PlanID, 1))}
	metadata, e := openMetadata(ctx, id)
	if e != nil {
		return plan, e
	}
	defer metadata.Close()
	m, e := metadata.Installation(ctx)
	if e != nil {
		return plan, e
	}
	plan.ExpectedActiveRevision = m.ActiveRevision
	records, e := metadata.PendingProvisions(ctx)
	if e != nil {
		return plan, e
	}
	selected, e := ownedPurgeClosure(records, m)
	if e != nil {
		return plan, e
	}
	keys := map[string]bool{}
	for _, record := range selected {
		key := record.Kind + ":" + record.Identity
		if keys[key] {
			return plan, errors.New("multiple live object identities require reconciliation before purge review")
		}
		keys[key] = true
		digest, e := ObjectObservationDigest(record.Observed)
		if e != nil {
			return plan, e
		}
		plan.Scope = append(plan.Scope, ApprovedObject{Kind: record.Kind, Identity: record.Identity, Action: "remove", ObservationDigest: digest})
	}
	sort.Slice(plan.Scope, func(i, j int) bool {
		a, b := plan.Scope[i], plan.Scope[j]
		if a.Kind == b.Kind {
			return a.Identity < b.Identity
		}
		return a.Kind < b.Kind
	})
	plan.PlanDigest, e = PurgePlanDigest(plan)
	return plan, e
}
func preflightCompletedScope(ctx context.Context, id RuntimeInstallationID, scope []ApprovedObject) error {
	metadata, e := openMetadata(ctx, id)
	if e != nil {
		return e
	}
	defer metadata.Close()
	for _, approval := range scope {
		records, e := metadata.ObjectProvisions(ctx, approval.Kind, approval.Identity)
		if e != nil {
			return e
		}
		for _, original := range records {
			if original.State != "OBSERVED" || !original.ProductCreated || original.ExistedBefore {
				continue
			}
			sum, e := ObjectObservationDigest(original.Observed)
			if e != nil {
				return e
			}
			if sum != approval.ObservationDigest {
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
