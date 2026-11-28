package runtime

import (
	"encoding/json"
	"net/netip"
	"path/filepath"
	"regexp"

	"github.com/thirdscam/chatanium/internal/host"
)

// DefaultInstallationConfig proposes finite, visible operator choices only.
// The installation owner supplies observed identity/bundle/paths; no path is
// created, image prepared, grant issued or runtime epoch started here.
func DefaultInstallationConfig(id, bundle string, paths host.InstallationPaths) ([]byte, error) {
	config := defaultConfig(id, bundle, paths.StorageRoot, filepath.Join(paths.RunRoot, "instances"))
	config.Host.QuotaBackend = "xfs-project"
	config.Limits.PersistentInodeLimit = 64 << 10
	config.Limits.ScratchInodeLimit = 16 << 10
	config.Limits.UploadRecordsPerInstance = 32
	config.Limits.UploadRecordsPerHost = 256
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(struct {
		Config
		Modules []moduleJSON `json:"modules"`
	}{config, []moduleJSON{}}, "", "  ")
}

var imagePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.:-]*/[a-zA-Z0-9][a-zA-Z0-9._/-]*@sha256:[a-f0-9]{64}$`)
var interfacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
var ulaNetwork = netip.MustParsePrefix("fc00::/7")
var publicIPv6Network = netip.MustParsePrefix("2000::/3")

func (c Config) validLegacyHost() bool {
	h, l := c.Host, c.Limits
	if h.QuotaBackend != "xfs-project" || l.PersistentInodeLimit <= 0 || l.ScratchInodeLimit <= 0 {
		return false
	}
	n := h.Network
	if n.Profile == host.NetworkNone {
		return !n.hasLegacySettings()
	}
	if (n.Profile != host.NetworkPublicV4 && n.Profile != host.NetworkPublicDual) || (n.Profile == host.NetworkPublicDual) != n.IPv6 {
		return false
	}
	if n.FirewallBackend != "iptables" || !n.IPv4 || len(n.Resolvers) == 0 || n.HostPublicAddresses == nil || n.InternalPrefixes == nil || n.InfrastructurePrefixes == nil || n.MetadataDestinations == nil {
		return false
	}
	pool4, poolErr := netip.ParsePrefix(n.IPv4Pool)
	source4, sourceErr := netip.ParseAddr(n.Source4)
	if poolErr != nil || !pool4.Addr().Is4() || pool4 != pool4.Masked() || pool4.Bits() < 8 || pool4.Bits() > 30 || n.InventoryRevision == "" || !interfacePattern.MatchString(n.Uplink4) || sourceErr != nil || !source4.Is4() || !source4.IsGlobalUnicast() || len(n.HostPublicAddresses) == 0 || len(n.MetadataDestinations) == 0 {
		return false
	}
	if n.IPv6 {
		pool6, err := netip.ParsePrefix(n.IPv6Pool)
		source6, sourceErr := netip.ParseAddr(n.Source6)
		if err != nil || !pool6.Addr().Is6() || pool6 != pool6.Masked() || pool6.Bits() < 48 || pool6.Bits() > 126 || !ulaNetwork.Contains(pool6.Addr()) || !interfacePattern.MatchString(n.Uplink6) || sourceErr != nil || !publicIPv6Network.Contains(source6) {
			return false
		}
	} else if n.IPv6Pool != "" || n.Uplink6 != "" || n.Source6 != "" {
		return false
	}
	resolver4, resolver6 := false, false
	for group, addresses := range [][]string{n.Resolvers, n.HostPublicAddresses} {
		for _, s := range addresses {
			a, e := netip.ParseAddr(s)
			if e != nil || a.Is4In6() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || (!n.IPv6 && a.Is6()) {
				return false
			}
			if group == 0 {
				resolver4 = resolver4 || a.Is4()
				resolver6 = resolver6 || a.Is6()
			}
		}
	}
	if !resolver4 || (n.IPv6 && !resolver6) {
		return false
	}
	for _, ss := range [][]string{n.InternalPrefixes, n.InfrastructurePrefixes, n.MetadataDestinations} {
		for _, s := range ss {
			if _, e := netip.ParsePrefix(s); e != nil {
				if _, e = netip.ParseAddr(s); e != nil {
					return false
				}
			}
		}
	}
	return true
}

func (s ModuleSpec) validLegacyTarget() bool {
	return (imagePattern.MatchString(s.ImageDigest) || recordImagePattern.MatchString(s.ImageDigest)) && cleanAbsolute(s.Entrypoint[0])
}
