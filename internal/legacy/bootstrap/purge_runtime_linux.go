//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/legacy/host"
	"time"
)

func purgeNetworkConfig(s *ownedSession) host.NetworkConfig {
	c, m := s.config, s.manifest
	return host.NetworkConfig{Profile: profile(c), IPv4Pool: c.Host.Network.IPv4Pool, IPv6Pool: c.Host.Network.IPv6Pool, InventoryRevision: c.Host.Network.InventoryRevision, Uplink4: c.Host.Network.Uplink4, Uplink6: c.Host.Network.Uplink6, Source4: c.Host.Network.Source4, Source6: c.Host.Network.Source6, Resolvers: c.Host.Network.Resolvers, HostPublicAddresses: c.Host.Network.HostPublicAddresses, InternalPrefixes: append(append([]string{}, c.Host.Network.InternalPrefixes...), c.Host.Network.InfrastructurePrefixes...), MetadataPrefixes: c.Host.Network.MetadataDestinations, OperationTimeout: time.Duration(c.Limits.HostOperationDeadline), RunRoot: m.Paths.RunRoot}
}
func purgeSessionBundle(ctx context.Context, s *ownedSession) (bundle.Verified, error) {
	if verified, e := installedBundle(ctx, s.manifest); e == nil {
		return verified, nil
	}
	records, e := s.store.PendingProvisions(ctx)
	if e != nil {
		return bundle.Verified{}, e
	}
	for _, record := range records {
		if record.Kind != "bundle" || record.State != "OBSERVED" || record.CleanupState == "COMPLETE" {
			continue
		}
		private, e := purgeHelperArtifact(ctx, s.store, s.manifest, record)
		if e != nil {
			return bundle.Verified{}, e
		}
		if !private {
			continue
		}
		var p host.ProvisionProperties
		if e = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); e != nil {
			return bundle.Verified{}, e
		}
		raw, e := readProtected(p.Path+"/manifest.json", bundle.MaxManifestBytes)
		if e != nil {
			continue
		}
		manifest, e := bundle.VerifyManifest(raw)
		if e != nil || manifest.Digest != s.manifest.BundleDigest {
			continue
		}
		verified, e := bundle.VerifyDirectory(ctx, p.Path, manifest)
		if e == nil {
			return verified, nil
		}
	}
	return bundle.Verified{}, errors.New("purge has no retained verified helper closure")
}
func acquirePurgeRuntime(ctx context.Context, id RuntimeInstallationID) (session *ownedSession, retErr error) {
	session, e := openPurgeOwner(ctx, id)
	if e != nil {
		return nil, e
	}
	defer func() {
		if retErr != nil {
			closeMaintenance(session)
		}
	}()
	m, c := session.manifest, session.config
	verified, e := purgeSessionBundle(ctx, session)
	if e != nil {
		return session, e
	}
	if e = host.AttachBacking(ctx, m, session.store, session.systemd); e != nil {
		return session, e
	}
	sc := supervisorConfig(m, c)
	session.storage, e = host.OpenStorageForCleanup(ctx, sc, session.store, session.systemd)
	if e != nil {
		return session, e
	}
	session.images, e = host.NewImageManager(imageConfig(m, verified, session.owner, nil), session.store, session.systemd, session.storage)
	if e != nil {
		return session, e
	}
	if e = session.images.Recover(ctx); e != nil {
		return session, e
	}
	session.network, e = host.NewNetworkForReconcile(ctx, purgeNetworkConfig(session), session.store, session.systemd)
	if e != nil {
		return session, e
	}
	if e = session.network.ReconcileOwned(ctx); e != nil {
		return session, e
	}
	platform, e := host.NewGvxPlatform(host.GvxPlatformConfig{Owner: session.owner, Bundle: verified, Sandbox: m.Identities.Sandbox, StartupDeadline: time.Duration(c.Defaults.StartupDeadline), OperationTimeout: sc.OperationTimeout, TerminationDeadline: time.Duration(c.Limits.TerminationDeadline)}, session.store, session.systemd, session.storage, session.network, session.images)
	if e != nil {
		return session, e
	}
	session.supervisor, e = host.NewSupervisor(ctx, sc, platform, session.store, session.lease)
	return session, e
}
func reconcilePurgeNetwork(ctx context.Context, s *ownedSession) error {
	network, e := host.NewNetworkForReconcile(ctx, purgeNetworkConfig(s), s.store, s.systemd)
	if e != nil {
		return e
	}
	defer network.Close()
	if e = network.ReconcileOwned(ctx); e != nil {
		return e
	}
	proof, e := s.systemd.RecoverHelpers(ctx)
	if e == nil {
		s.cleanupEvidence = proof
	}
	return e
}
