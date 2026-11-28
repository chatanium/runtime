//go:build linux

package host

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"

	sharedhost "github.com/thirdscam/chatanium/internal/host"
)

type networkAddress struct {
	Family    string   `json:"family"`
	Local     string   `json:"local"`
	PrefixLen int      `json:"prefixlen"`
	Scope     string   `json:"scope"`
	Flags     []string `json:"flags"`
}
type networkLink struct {
	IfIndex   int              `json:"ifindex"`
	IfName    string           `json:"ifname"`
	LinkIndex int              `json:"link_index"`
	Address   string           `json:"address"`
	Flags     []string         `json:"flags"`
	MTU       int              `json:"mtu"`
	AddrInfo  []networkAddress `json:"addr_info"`
	LinkInfo  struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}
type networkRoute struct {
	Dst      string   `json:"dst"`
	Dev      string   `json:"dev"`
	Gateway  string   `json:"gateway"`
	PrefSrc  string   `json:"prefsrc"`
	Src      string   `json:"src"`
	Table    any      `json:"table"`
	Type     string   `json:"type"`
	Protocol string   `json:"protocol"`
	Scope    string   `json:"scope"`
	Flags    []string `json:"flags"`
}
type networkNeighbor struct {
	Dst    string   `json:"dst"`
	Dev    string   `json:"dev"`
	LLAddr string   `json:"lladdr"`
	State  []string `json:"state"`
}

func (n *Network) links(ctx context.Context, ns string) ([]networkLink, error) {
	raw, err := n.ip(ctx, ns, "-j", "-d", "address", "show")
	if err != nil {
		return nil, err
	}
	var links []networkLink
	err = networkJSON(raw, &links)
	return links, err
}
func (n *Network) routes(ctx context.Context, ns, family string) ([]networkRoute, error) {
	raw, err := n.ip(ctx, ns, "-j", family, "route", "show", "table", "all")
	if err != nil {
		return nil, err
	}
	var routes []networkRoute
	err = networkJSON(raw, &routes)
	return routes, err
}
func (n *Network) occupied(ctx context.Context, allocations []*networkAllocation) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, a := range allocations {
		if a.Record.State == "CLEANED" {
			continue
		}
		for _, s := range []string{a.Record.IPv4Prefix, a.Record.IPv6Prefix} {
			if s != "" {
				p, e := netip.ParsePrefix(s)
				if e != nil {
					return nil, e
				}
				out = append(out, p)
			}
		}
	}
	links, err := n.links(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		for _, a := range link.AddrInfo {
			ip, e := netip.ParseAddr(a.Local)
			if e != nil {
				return nil, e
			}
			out = append(out, netip.PrefixFrom(ip, a.PrefixLen).Masked())
		}
	}
	for _, family := range []string{"-4", "-6"} {
		routes, e := n.routes(ctx, "", family)
		if e != nil {
			return nil, e
		}
		for _, r := range routes {
			if r.Dst == "default" || r.Dst == "" {
				continue
			}
			p, e := parseAddressPrefix(r.Dst)
			if e != nil {
				return nil, e
			}
			out = append(out, p)
		}
	}
	for _, s := range append(append(append([]string{}, n.cfg.HostPublicAddresses...), n.cfg.InternalPrefixes...), n.cfg.MetadataPrefixes...) {
		p, e := parseAddressPrefix(s)
		if e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, nil
}
func (n *Network) blocked(ctx context.Context) ([]netip.Prefix, error) {
	out := append([]netip.Prefix{}, specialPurposePrefixes...)
	for _, s := range append(append(append([]string{}, n.cfg.HostPublicAddresses...), n.cfg.InternalPrefixes...), n.cfg.MetadataPrefixes...) {
		p, e := parseAddressPrefix(s)
		if e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	for _, s := range []string{n.cfg.IPv4Pool, n.cfg.IPv6Pool} {
		if s != "" {
			p, e := netip.ParsePrefix(s)
			if e != nil {
				return nil, e
			}
			out = append(out, p)
		}
	}
	links, e := n.links(ctx, "")
	if e != nil {
		return nil, e
	}
	for _, l := range links {
		for _, a := range l.AddrInfo {
			ip, e := netip.ParseAddr(a.Local)
			if e != nil {
				return nil, e
			}
			out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	for _, s := range []string{n.cfg.Source4, n.cfg.Source6} {
		if s != "" {
			a, e := netip.ParseAddr(s)
			if e != nil {
				return nil, e
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return networkSortedPrefixes(out), nil
}
func (n *Network) preflight(ctx context.Context, a *networkAllocation) error {
	r := a.Record
	if r.Profile == sharedhost.NetworkNone {
		return nil
	}
	if err := n.verifyAllocationConflicts(ctx, a); err != nil {
		return err
	}
	required := n.cfg
	required.Profile = r.Profile
	required.Uplink4, required.Uplink6 = r.Uplink4, r.Uplink6
	required.Source4, required.Source6 = r.Source4, r.Source6
	if _, err := ObserveNetworkPrerequisites(ctx, required); err != nil {
		return err
	}
	for _, family := range []int{4, 6} {
		raw, e := n.run(ctx, map[int]string{4: "iptables", 6: "ip6tables"}[family], "", "--version")
		if e != nil || !strings.Contains(string(raw), "nf_tables") {
			return prerequisite(errors.New("bundled iptables-nft filtering required"))
		}
		if _, e = n.tables(ctx, family, "", "filter", "-S"); e != nil {
			return e
		}
		if family == 4 || r.Profile == sharedhost.NetworkPublicDual {
			if _, e = n.tables(ctx, family, "", "nat", "-S"); e != nil {
				return prerequisite(errors.New("selected family NAT support unavailable"))
			}
		}
	}
	return nil
}
func (n *Network) inventoryDigest(ctx context.Context) (string, error) {
	var parts [][]byte
	links, e := n.links(ctx, "")
	if e != nil {
		return "", e
	}
	// Every generation verifies its own links/routes separately. Other durable
	// allocations are already excluded by pool policy and cannot change this
	// generation's selected host uplink/source authority.
	allocations, e := networkAllocations()
	if e != nil {
		return "", e
	}
	owned := make(map[string]bool)
	for _, a := range allocations {
		if a.Record.State != "CLEANED" {
			owned[a.Record.HostInterface] = true
			owned[a.Record.PeerInterface] = true
		}
	}
	links = slices.DeleteFunc(links, func(l networkLink) bool { return owned[l.IfName] })
	raw, e := json.Marshal(links)
	if e != nil {
		return "", e
	}
	parts = append(parts, raw, []byte(n.cfg.InventoryRevision))
	for _, family := range []string{"-4", "-6"} {
		routes, e := n.routes(ctx, "", family)
		if e != nil {
			return "", e
		}
		routes = slices.DeleteFunc(routes, func(r networkRoute) bool { return owned[r.Dev] })
		raw, e = json.Marshal(routes)
		if e != nil {
			return "", e
		}
		parts = append(parts, raw)
		raw, e = n.ip(ctx, "", "-j", family, "rule", "show")
		if e != nil {
			return "", e
		}
		parts = append(parts, raw)
	}
	return networkDigest(parts...), nil
}
func (n *Network) verifyLink(ctx context.Context, a *networkAllocation) error {
	links, e := n.links(ctx, "")
	if e != nil {
		return e
	}
	r := a.Record
	for _, l := range links {
		if l.IfName == r.HostInterface {
			if l.IfIndex != r.HostIfIndex || l.Address != r.HostMAC || l.LinkInfo.Kind != "veth" || (l.LinkIndex != 0 && l.LinkIndex != r.PeerIfIndex) {
				return errors.New("host veth identity mismatch")
			}
			return nil
		}
	}
	return errors.New("owned host veth missing")
}
func (n *Network) topology(ctx context.Context, a *networkAllocation) (map[string]string, error) {
	if err := networkObserveNamespace(a); err != nil {
		return nil, err
	}
	out := make(map[string]string)
	r := a.Record
	namespaces := []string{r.NetnsPath}
	if r.Profile != sharedhost.NetworkNone {
		namespaces = []string{"", r.NetnsPath}
	}
	for _, ns := range namespaces {
		links, e := n.links(ctx, ns)
		if e != nil {
			return nil, e
		}
		var selected []networkLink
		for _, l := range links {
			if ns != "" || l.IfName == r.HostInterface {
				selected = append(selected, l)
			}
		}
		if ns != "" && r.Profile == sharedhost.NetworkNone {
			if len(selected) != 1 || selected[0].IfName != "lo" || !slices.Contains(selected[0].Flags, "UP") {
				return nil, errors.New("NONE namespace is not loopback-only")
			}
		}
		if r.Profile != sharedhost.NetworkNone {
			iface, mac, index, addr4, addr6 := r.HostInterface, r.HostMAC, r.HostIfIndex, r.HostIPv4, r.HostIPv6
			if ns != "" {
				iface, mac, index, addr4, addr6 = r.PeerInterface, r.PeerMAC, r.PeerIfIndex, r.PeerIPv4, r.PeerIPv6
			}
			found := false
			for _, l := range selected {
				if l.IfName == "lo" && ns != "" {
					continue
				}
				if l.IfName != iface || l.Address != mac || l.IfIndex != index || l.LinkInfo.Kind != "veth" {
					return nil, errors.New("unexpected endpoint interface identity")
				}
				found = true
				have4, have6 := false, addr6 == ""
				for _, ad := range l.AddrInfo {
					if ad.Local == addr4 && ad.PrefixLen == 30 {
						have4 = true
					} else if addr6 != "" && ad.Local == addr6 && ad.PrefixLen == 126 {
						have6 = true
					} else {
						return nil, errors.New("unexpected endpoint address")
					}
				}
				if !have4 || !have6 {
					return nil, errors.New("endpoint static addresses missing")
				}
			}
			if !found {
				return nil, errors.New("endpoint interface missing")
			}
		}
		raw, e := json.Marshal(selected)
		if e != nil {
			return nil, e
		}
		out[ns+"/links"] = string(raw)
		for _, family := range []string{"-4", "-6"} {
			routes, e := n.routes(ctx, ns, family)
			if e != nil {
				return nil, e
			}
			var selectedRoutes []networkRoute
			for _, route := range routes {
				if ns != "" || route.Dev == r.HostInterface {
					selectedRoutes = append(selectedRoutes, route)
				}
			}
			if e = networkValidateRoutes(r, ns != "", family, selectedRoutes); e != nil {
				return nil, e
			}
			if ns != "" {
				rules, e := n.ip(ctx, ns, "-j", family, "rule", "show")
				if e != nil {
					return nil, e
				}
				out[ns+family+"/rules"] = string(rules)
			}
			raw, e = json.Marshal(selectedRoutes)
			if e != nil {
				return nil, e
			}
			out[ns+family+"/routes"] = string(raw)
			raw, e = n.ip(ctx, ns, "-j", family, "neigh", "show")
			if e != nil {
				return nil, e
			}
			var neighbors []networkNeighbor
			if e = networkJSON(raw, &neighbors); e != nil {
				return nil, e
			}
			var selectedNeighbors []networkNeighbor
			for _, v := range neighbors {
				if ns != "" || v.Dev == r.HostInterface {
					selectedNeighbors = append(selectedNeighbors, v)
				}
			}
			if r.Profile != sharedhost.NetworkNone && (family == "-4" || r.Profile == sharedhost.NetworkPublicDual) {
				peer, mac, dev := r.PeerIPv4, r.PeerMAC, r.HostInterface
				if family == "-6" {
					peer = r.PeerIPv6
				}
				if ns != "" {
					peer, mac, dev = r.HostIPv4, r.HostMAC, r.PeerInterface
					if family == "-6" {
						peer = r.HostIPv6
					}
				}
				if len(selectedNeighbors) != 1 || selectedNeighbors[0].Dst != peer || selectedNeighbors[0].LLAddr != mac || selectedNeighbors[0].Dev != dev || !slices.Contains(selectedNeighbors[0].State, "PERMANENT") {
					return nil, errors.New("permanent ARP/NDP identity mismatch")
				}
			} else if len(selectedNeighbors) != 0 {
				return nil, errors.New("unexpected endpoint neighbors")
			}
			raw, e = json.Marshal(selectedNeighbors)
			if e != nil {
				return nil, e
			}
			out[ns+family+"/neighbors"] = string(raw)
		}
	}
	return out, nil
}
func (n *Network) verify(ctx context.Context, a *networkAllocation, open bool) error {
	actual, e := n.topology(ctx, a)
	if e != nil {
		return e
	}
	if !networkEqualSnapshots(a.Topology, actual) {
		return errors.New("owned network topology drift")
	}
	if a.Record.Profile == sharedhost.NetworkNone {
		return nil
	}
	if e = n.verifyRules(ctx, a); e != nil {
		return e
	}
	digest, e := n.inventoryDigest(ctx)
	if e != nil {
		return e
	}
	if digest != a.HostInventoryDigest {
		return errors.New("host route/address/rule inventory drift")
	}
	links, e := n.links(ctx, "")
	if e != nil {
		return e
	}
	for _, link := range links {
		if link.IfName == a.Record.HostInterface && slices.Contains(link.Flags, "UP") != open {
			return errors.New("physical egress barrier differs from durable policy")
		}
	}
	return nil
}
func networkBootID() (string, error) {
	raw, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return "", e
	}
	id := strings.TrimSpace(string(raw))
	if len(id) != 36 {
		return "", errors.New("invalid host boot identity")
	}
	return id, nil
}
func networkValidateRoutes(r NetworkRecord, peer bool, family string, routes []networkRoute) error {
	prefix, host, iface := r.IPv4Prefix, r.HostIPv4, r.HostInterface
	if family == "-6" {
		prefix, host = r.IPv6Prefix, r.HostIPv6
	}
	if peer {
		iface = r.PeerInterface
	}
	active := r.Profile != sharedhost.NetworkNone && prefix != ""
	connected, defaults := 0, 0
	for _, route := range routes {
		if peer && route.Dev == "lo" && route.Gateway == "" {
			p, e := parseAddressPrefix(route.Dst)
			if e == nil && (netip.MustParsePrefix("127.0.0.0/8").Overlaps(p) || netip.MustParsePrefix("::1/128").Overlaps(p)) {
				continue
			}
			return errors.New("unexpected loopback route")
		}
		if !active {
			return errors.New("inactive family has an external route")
		}
		if route.Dev != iface {
			return errors.New("route uses unexpected endpoint interface")
		}
		if route.Dst == "default" || route.Dst == "0.0.0.0/0" || route.Dst == "::/0" {
			if !peer || route.Gateway != host {
				return errors.New("endpoint default route has wrong gateway")
			}
			defaults++
			continue
		}
		p, e := parseAddressPrefix(route.Dst)
		if e != nil {
			return e
		}
		allocated := netip.MustParsePrefix(prefix)
		if !allocated.Contains(p.Addr()) || p.Bits() < allocated.Bits() || route.Gateway != "" {
			return errors.New("route escapes allocated endpoint prefix")
		}
		if p == allocated && route.Type != "local" && route.Type != "broadcast" {
			connected++
		}
	}
	if active && (connected != 1 || peer && defaults != 1 || !peer && defaults != 0) {
		return errors.New("required connected/default route is absent or duplicated")
	}
	return nil
}
func (n *Network) verifyAllocationConflicts(ctx context.Context, a *networkAllocation) error {
	var reserved []netip.Prefix
	for _, s := range []string{a.Record.IPv4Prefix, a.Record.IPv6Prefix} {
		if s != "" {
			p, e := netip.ParsePrefix(s)
			if e != nil {
				return e
			}
			reserved = append(reserved, p)
		}
	}
	conflicts := func(p netip.Prefix) bool {
		for _, q := range reserved {
			if q.Overlaps(p) {
				return true
			}
		}
		return false
	}
	allocations, e := networkAllocations()
	if e != nil {
		return e
	}
	for _, other := range allocations {
		if other.Record.Generation == a.Record.Generation && other.Owner.RuntimeInstallationID == a.Owner.RuntimeInstallationID || other.Record.State == "CLEANED" {
			continue
		}
		for _, s := range []string{other.Record.IPv4Prefix, other.Record.IPv6Prefix} {
			if s != "" {
				p, e := netip.ParsePrefix(s)
				if e != nil {
					return e
				}
				if conflicts(p) {
					return errors.New("network prefix conflicts with another durable allocation")
				}
			}
		}
	}
	links, e := n.links(ctx, "")
	if e != nil {
		return e
	}
	ownLink := false
	for _, link := range links {
		if a.Record.HostIfIndex > 0 && link.IfIndex == a.Record.HostIfIndex && link.IfName == a.Record.HostInterface && link.Address == a.Record.HostMAC {
			ownLink = true
			continue
		}
		for _, ad := range link.AddrInfo {
			ip, e := netip.ParseAddr(ad.Local)
			if e != nil {
				return e
			}
			if conflicts(netip.PrefixFrom(ip, ad.PrefixLen).Masked()) {
				return errors.New("network prefix conflicts with host address inventory")
			}
		}
	}
	for _, family := range []string{"-4", "-6"} {
		routes, e := n.routes(ctx, "", family)
		if e != nil {
			return e
		}
		for _, route := range routes {
			if ownLink && route.Dev == a.Record.HostInterface || route.Dst == "" || route.Dst == "default" || route.Dst == "0.0.0.0/0" || route.Dst == "::/0" {
				continue
			}
			p, e := parseAddressPrefix(route.Dst)
			if e != nil {
				return e
			}
			if conflicts(p) {
				return errors.New("network prefix conflicts with non-default host route")
			}
		}
	}
	return nil
}
