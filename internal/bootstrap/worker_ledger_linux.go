//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"strings"
)

func workerLimits() host.ResourceLimits {
	return host.ResourceLimits{NanoCPUs: 2e9, MemoryBytes: 2 << 30, Pids: 512}
}
func observeWorkerLedger(ctx context.Context, store *host.Store, ledger, name, revision string, expected *host.UnitIdentity) error {
	records, e := store.UnitProvisions(ctx, name)
	if e != nil {
		return e
	}
	submitted := false
	for _, record := range records {
		if !strings.HasPrefix(record.ID, "systemd-") {
			continue
		}
		var desired, native host.ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); e != nil {
			return e
		}
		if desired.Source != string(bundle.Worker) {
			continue
		}
		submitted = true
		if record.State != "OBSERVED" {
			continue
		}
		if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &native); e != nil {
			return e
		}
		if native.Unit == nil || expected != nil && *native.Unit != *expected {
			continue
		}
		native.Name = name
		native.Revision = revision
		native.ProductCreated = true
		if len(native.TransportPipes) == 0 {
			native.TransportPipes = desired.TransportPipes
		}
		absence := native.Absence
		previous, e := store.Provision(ctx, ledger)
		if e != nil {
			return e
		}
		alreadyAbsent := false
		if previous.State == "OBSERVED" {
			var old host.ProvisionProperties
			if e = gvxcontract.DecodeStrict(previous.Observed.Attributes, 64<<10, 16, &old); e != nil {
				return e
			}
			alreadyAbsent = old.Absence != nil
		}
		if alreadyAbsent {
			return store.ObserveProvision(ctx, ledger, host.ObjectObservation{Identity: name, Attributes: provisionJSON(native)})
		}
		native.Absence = nil
		if e = store.ObserveProvision(ctx, ledger, host.ObjectObservation{Identity: name, Attributes: provisionJSON(native)}); e != nil {
			return e
		}
		if absence != nil {
			native.Absence = absence
			return store.ObserveProvision(ctx, ledger, host.ObjectObservation{Identity: name, Attributes: provisionJSON(native)})
		}
		return nil
	}
	if !submitted && expected == nil {
		return store.ObserveProvision(ctx, ledger, host.ObjectObservation{Identity: name, Attributes: provisionJSON(host.ProvisionProperties{Name: name, Revision: revision, Rejection: "never-submitted", ProductCreated: true})})
	}
	return errors.New("worker has no matching captured native observation")
}
func recoverWorkerLedgers(ctx context.Context, s *ownedSession, proof host.CleanupEvidence) error {
	records, e := s.store.PendingProvisions(ctx)
	if e != nil {
		return e
	}
	for _, record := range records {
		if record.Kind != "unit" || strings.HasPrefix(record.ID, "systemd-") || !strings.HasPrefix(record.Identity, "chatanium-worker-") || !strings.HasSuffix(record.Identity, ".service") {
			continue
		}
		var desired host.ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); e != nil {
			return e
		}
		var expected *host.UnitIdentity
		if record.State == "OBSERVED" {
			var observed host.ProvisionProperties
			if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &observed); e != nil {
				return e
			}
			expected = observed.Unit
		}
		if e = observeWorkerLedger(ctx, s.store, record.ID, record.Identity, desired.Revision, expected); e != nil {
			return e
		}
		current, e := s.store.Provision(ctx, record.ID)
		if e != nil {
			return e
		}
		var native host.ProvisionProperties
		if e = gvxcontract.DecodeStrict(current.Observed.Attributes, 64<<10, 16, &native); e != nil {
			return e
		}
		evidence := proof
		if native.Unit != nil {
			observed, e := s.systemd.RecoverOwnedUnit(ctx, native.Unit.Name, native.Unit.Generation, bundle.Worker, workerLimits())
			if e != nil {
				return e
			}
			if observed.Unit != *native.Unit {
				return errors.New("recovered worker invocation changed")
			}
			evidence, e = s.systemd.Settle(ctx, observed.Unit)
			if e != nil {
				return e
			}
			if e = observeWorkerLedger(ctx, s.store, record.ID, record.Identity, desired.Revision, native.Unit); e != nil {
				return e
			}
		}
		if e = s.store.CompleteProvisionCleanup(ctx, record.ID, evidence); e != nil {
			return e
		}
	}
	return nil
}
