//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/runtime"
	"os"
	"time"
)

func openOwner(ctx context.Context, id RuntimeInstallationID, mode RunMode) (*ownedSession, error) {
	return openOwnerFor(ctx, id, mode, false)
}
func openPurgeOwner(ctx context.Context, id RuntimeInstallationID) (*ownedSession, error) {
	return openOwnerFor(ctx, id, Foreground, true)
}
func openOwnerFor(ctx context.Context, id RuntimeInstallationID, mode RunMode, purge bool) (*ownedSession, error) {
	return openOwnerWithBundle(ctx, id, mode, purge, nil)
}

func openOwnerWithBundle(ctx context.Context, id RuntimeInstallationID, mode RunMode, purge bool, selectBundle func(context.Context, *host.Store, host.InstallationManifest) (bundle.Verified, error)) (*ownedSession, error) {
	if e := rootRequired(); e != nil {
		return nil, e
	}
	store, m, e := openInstallation(ctx, id)
	if e != nil {
		return nil, e
	}
	lease, e := store.AcquireLease(ctx)
	if e != nil {
		store.Close()
		return nil, e
	}
	fail := func(cause error) (*ownedSession, error) { lease.Close(); store.Close(); return nil, cause }
	if purge {
		if e = preparePurgeAdmission(ctx, store); e != nil {
			return fail(e)
		}
	}
	var verified bundle.Verified
	if selectBundle == nil {
		verified, e = recoveryBundle(ctx, store, m, purge)
	} else {
		verified, e = selectBundle(ctx, store, m)
	}
	if e != nil {
		return fail(e)
	}
	d, e := host.NewSystemd(ctx, verified)
	if e != nil {
		return fail(e)
	}
	var owner host.UnitIdentity
	if mode == Service {
		if e = validateServiceDefinition(ctx, store, m); e == nil {
			owner, e = d.CurrentServiceOwner(ctx, serviceName(id))
		}
	} else {
		owner, e = d.RegisterForegroundOwner(ctx, string(id))
	}
	if e != nil {
		d.Close()
		return fail(e)
	}
	if e = lease.BindOwner(ctx, owner); e != nil {
		d.Close()
		return fail(e)
	}
	if e = d.BindStore(store); e != nil {
		d.Close()
		return fail(e)
	}
	if selectBundle != nil {
		if e = d.BindOwner(ctx, owner); e != nil {
			d.Close()
			return fail(e)
		}
	}
	session := &ownedSession{id: id, manifest: m, store: store, lease: lease, systemd: d, owner: owner, events: make(chan workerRead, 16), done: make(chan struct{}), workerDone: make(chan struct{})}
	proof, e := d.RecoverHelpers(ctx)
	if e == nil {
		e = recoverWorkerLedgers(ctx, session, proof)
	}
	if e != nil {
		d.Close()
		return fail(e)
	}
	session.cleanupEvidence = proof
	if !purge {
		if e = ensureBootEphemeral(ctx, store, m, proof); e != nil {
			closeMaintenance(session)
			return nil, e
		}
	}
	revisionID := m.ActiveRevision
	if revisionID == "" {
		revisionID = m.PendingRevision
	}
	if revisionID != "" {
		revision, e := store.Revision(ctx, revisionID)
		if e != nil {
			closeMaintenance(session)
			return nil, e
		}
		session.config, e = runtime.DecodeConfig(revision.Config)
		if e != nil {
			closeMaintenance(session)
			return nil, e
		}
	}
	return session, nil
}
func recoveryBundle(ctx context.Context, store *host.Store, m host.InstallationManifest, purge bool) (bundle.Verified, error) {
	verified, installedErr := installedBundle(ctx, m)
	if installedErr == nil {
		return verified, nil
	}
	removing, lookup := hasPurgeBundleLineage(ctx, store, m)
	if lookup != nil {
		return bundle.Verified{}, lookup
	}
	if removing && !purge {
		return bundle.Verified{}, errors.New("retired helper closure can only be reacquired for explicit purge")
	}
	if !removing && !os.IsNotExist(installedErr) {
		return bundle.Verified{}, installedErr
	}
	source, e := configuredSource()
	if e != nil {
		return bundle.Verified{}, e
	}
	raw, e := source.Manifest()
	if e != nil {
		return bundle.Verified{}, e
	}
	manifest, e := bundle.VerifyManifest(raw)
	if e != nil {
		return bundle.Verified{}, e
	}
	if manifest.Digest != m.BundleDigest || !compatibleBundle(manifest, m) {
		return bundle.Verified{}, errors.New("reacquired launcher bundle is not installation-compatible")
	}
	if removing {
		return publishPurgeHelpers(ctx, store, m, source)
	}
	if _, e = os.Lstat(m.Paths.EngineRoot); os.IsNotExist(e) {
		if e = createDirectory(ctx, store, m.Paths.EngineRoot, 0755); e != nil {
			return bundle.Verified{}, e
		}
	} else if e != nil {
		return bundle.Verified{}, e
	}
	records, e := store.PendingProvisions(ctx)
	if e != nil {
		return bundle.Verified{}, e
	}
	intent := ""
	for _, record := range records {
		if record.Kind == "bundle" && record.Identity == m.Paths.EngineRoot {
			var p host.ProvisionProperties
			if e = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &p); e != nil {
				return bundle.Verified{}, e
			}
			if p.Digest != m.BundleDigest {
				return bundle.Verified{}, errors.New("recovery bundle intent digest differs")
			}
			intent = record.ID
			break
		}
	}
	if intent == "" {
		intent, e = recordIntent(ctx, store, "bundle", m.Paths.EngineRoot, host.ProvisionProperties{Path: m.Paths.EngineRoot, Digest: m.BundleDigest, ProductCreated: true}, false)
		if e != nil {
			return bundle.Verified{}, e
		}
	}
	verified, e = publishBundle(ctx, store, source, m.Paths.EngineRoot)
	if e != nil {
		return bundle.Verified{}, e
	}
	e = observeBundle(ctx, store, intent, m.Paths.EngineRoot, verified)
	return verified, e
}
func cleanupProvisioning(ctx context.Context, s *ownedSession) (CleanupReport, error) {
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	report := CleanupReport{InstallationID: s.id, DesiredRunState: "STOPPED", ObservedState: "unknown"}
	if e := s.store.SetDesired(cleanup, "STOPPED", newID()); e != nil {
		return report, e
	}
	m := s.manifest
	if m.Backing.Dev == 0 {
		upstream, e := s.systemd.RecoverHelpers(cleanup)
		if e != nil {
			return report, e
		}
		backing, storage, e := host.VerifyProvisioningDetached(cleanup, m, s.store)
		if e != nil {
			return report, e
		}
		if backing.Dev != 0 {
			s.manifest.Backing = backing
		}
		upstream.MountsAbsent = storage.MountsAbsent
		upstream.OpenReferencesAbsent = upstream.OpenReferencesAbsent && storage.OpenReferencesAbsent
		upstream.QuotaReclaimed = storage.QuotaReclaimed
		s.cleanupEvidence = upstream
		report.Complete = upstream.JobsAbsent && upstream.ProcessesAbsent && upstream.TransportsClosed && upstream.MountsAbsent && upstream.OpenReferencesAbsent && upstream.QuotaReclaimed
		if !report.Complete {
			return report, host.ErrCleanupIncomplete
		}
		report.ObservedState = "stopped"
		return report, nil
	}
	if e := host.AttachBacking(cleanup, m, s.store, s.systemd); e != nil {
		return report, e
	}
	sc := supervisorConfig(m, s.config)
	storage, e := host.OpenStorageForCleanup(cleanup, sc, s.store, s.systemd)
	if e != nil {
		return report, e
	}
	defer storage.Close()
	verified, e := purgeSessionBundle(cleanup, s)
	if e != nil {
		return report, e
	}
	images, e := host.NewImageManager(imageConfig(m, verified, s.owner, nil), s.store, s.systemd, storage)
	if e != nil {
		return report, e
	}
	if e = images.Recover(cleanup); e != nil {
		return report, e
	}
	proof, e := s.systemd.RecoverHelpers(cleanup)
	if e != nil {
		return report, e
	}
	quota, e := storage.ReclaimEvidence(cleanup)
	if e != nil {
		return report, e
	}
	if e = storage.Close(); e != nil {
		return report, e
	}
	proof.QuotaReclaimed = quota.QuotaReclaimed
	if e = host.DetachBacking(cleanup, m, s.store, s.systemd, proof); e != nil {
		return report, e
	}
	if e = completeEvidence(cleanup, m, &proof); e != nil {
		return report, e
	}
	s.cleanupEvidence = proof
	report.Complete = true
	report.ObservedState = "stopped"
	return report, nil
}
func recoverInitialization(ctx context.Context, s *ownedSession) (host.CleanupEvidence, error) {
	if s == nil || s.store == nil || s.lease == nil || s.systemd == nil {
		return host.CleanupEvidence{}, errors.New("initialization recovery requires the held native owner session")
	}
	m, e := s.store.Installation(ctx)
	if e != nil {
		return host.CleanupEvidence{}, e
	}
	if m.State != "RECOVERY_REQUIRED" || m.ActiveRevision != "" || m.DesiredRunState != "STOPPED" {
		return host.CleanupEvidence{}, errors.New("initialization recovery is limited to stopped never-active state")
	}
	if s.owner.Name == "" || s.systemd.Owner() != s.owner {
		return host.CleanupEvidence{}, errors.New("initialization recovery owner differs from the held session")
	}
	s.manifest = m
	if _, e = s.systemd.RecoverHelpers(ctx); e != nil {
		return host.CleanupEvidence{}, e
	}
	report, e := cleanupProvisioning(ctx, s)
	if e != nil || !report.Complete {
		return host.CleanupEvidence{}, errors.Join(e, host.ErrCleanupIncomplete)
	}
	if e = s.store.AssertRemovable(ctx); e != nil {
		return host.CleanupEvidence{}, e
	}
	return s.cleanupEvidence, nil
}
func cleanupLocked(ctx context.Context, id RuntimeInstallationID) (*ownedSession, error) {
	store, m, e := openInstallation(ctx, id)
	if e != nil {
		return nil, e
	}
	store.Close()
	if m.ActiveRevision == "" {
		session, e := maintenance(ctx, id)
		if e != nil {
			return nil, e
		}
		report, e := cleanupProvisioning(ctx, session)
		if e != nil || !report.Complete {
			closeMaintenance(session)
			return nil, errors.Join(e, host.ErrCleanupIncomplete)
		}
		return session, nil
	}
	session, e := acquireSession(ctx, id, Foreground)
	if e != nil {
		return nil, e
	}
	report, e := DrainOwnedSession(ctx, OwnedSession{session})
	if e != nil || !report.Complete {
		closeMaintenance(session)
		return nil, errors.Join(e, host.ErrCleanupIncomplete)
	}
	if e = session.supervisor.Close(); e != nil {
		closeMaintenance(session)
		return nil, e
	}
	session.supervisor = nil
	return session, nil
}
