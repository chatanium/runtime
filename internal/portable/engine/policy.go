package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

type NetworkMode string

const (
	NetworkNone           NetworkMode = "NONE"
	NetworkPublicInternet NetworkMode = "PUBLIC_INTERNET"
)

type AddressFamily string

// Only IPv4 is enabled: v0.22 provisions only an IPv4 NAT address and
// default route; parser support for IPv6 does not establish an IPv6 data path.
const IPv4 AddressFamily = "ipv4"

type NetworkGrant struct {
	Mode   NetworkMode
	Family AddressFamily
	DNS    []netip.Addr
	// Excluded covers host interfaces, internal networks, other instances,
	// and operator-registered public NAT aliases from the approved review.
	Excluded                           []netip.Prefix
	TXBPS, RXBPS                       uint64
	AllowUnlimitedTX, AllowUnlimitedRX bool
}

const (
	denyPolicyJSON = `{"egress":{"default":"deny"},"ingress":{"default":"deny"}}`
	maxPolicyBytes = 64 << 10
	maxPolicyRules = 1024
	maxNetBPS      = 1_000_000_000_000
)

type plannedNetwork struct {
	mode     NetworkMode
	dns      []netip.Addr
	excluded []netip.Prefix
	tx, rx   uint64
	policy   json.RawMessage
	digest   string
}

type natPolicy struct {
	Egress  policyDirection `json:"egress"`
	Ingress policyDirection `json:"ingress"`
}

type policyDirection struct {
	Default string       `json:"default"`
	Rules   []policyRule `json:"rules,omitempty"`
}

type policyRule struct {
	Action    string `json:"action"`
	CIDR      string `json:"cidr,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Ports     string `json:"ports,omitempty"`
	GuestCIDR string `json:"guest_cidr,omitempty"`
}

var specialIPv4 = func() []netip.Prefix {
	var p []netip.Prefix
	for _, raw := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	} {
		p = append(p, netip.MustParsePrefix(raw))
	}
	return p
}()

func planNetwork(g NetworkGrant) (plannedNetwork, error) {
	p := plannedNetwork{mode: g.Mode}
	switch g.Mode {
	case NetworkNone:
		if g.Family != "" || len(g.DNS) != 0 || len(g.Excluded) != 0 || g.TXBPS != 0 || g.RXBPS != 0 || g.AllowUnlimitedTX || g.AllowUnlimitedRX {
			return p, errors.New("NONE cannot carry NAT settings")
		}
		return p, nil
	case NetworkPublicInternet:
	default:
		return p, errors.New("network mode must be explicitly NONE or PUBLIC_INTERNET")
	}
	if g.Family != IPv4 {
		return p, fmt.Errorf("%w: portable GVX NAT requires an approved IPv4-only profile", ErrUnsupportedTarget)
	}
	if g.TXBPS > maxNetBPS || g.RXBPS > maxNetBPS || (g.TXBPS == 0) != g.AllowUnlimitedTX || (g.RXBPS == 0) != g.AllowUnlimitedRX {
		return p, errors.New("NAT requires valid bit/s rates in both directions and explicit approval for each unlimited direction")
	}
	if len(g.DNS) == 0 || len(g.DNS) > (maxPolicyRules-7)/2 || len(g.Excluded) > maxPolicyRules-len(specialIPv4)-7-2*len(g.DNS) {
		return p, errors.New("NAT requires at least one approved numeric DNS server and a bounded ruleset")
	}
	p.tx, p.rx = g.TXBPS, g.RXBPS
	p.excluded = append(make([]netip.Prefix, 0, len(specialIPv4)+len(g.Excluded)), specialIPv4...)
	for _, prefix := range g.Excluded {
		normalized, err := normalizePrefix(prefix)
		if err != nil {
			return p, err
		}
		if normalized.Addr().Is4() {
			p.excluded = append(p.excluded, normalized)
		}
	}
	slices.SortFunc(p.excluded, func(a, b netip.Prefix) int {
		if byAddress := a.Addr().Compare(b.Addr()); byAddress != 0 {
			return byAddress
		}
		return a.Bits() - b.Bits()
	})
	p.excluded = slices.Compact(p.excluded)
	seenDNS := make(map[netip.Addr]bool, len(g.DNS))
	for _, addr := range g.DNS {
		addr = addr.Unmap()
		if !addr.Is4() || !addr.IsGlobalUnicast() || p.blocks(addr) || seenDNS[addr] {
			return p, fmt.Errorf("approved DNS %q is not a distinct permitted public IPv4 address", addr)
		}
		seenDNS[addr] = true
		p.dns = append(p.dns, addr)
	}

	rules := make([]policyRule, 0, len(p.excluded)+2*len(p.dns)+7)
	appendDNS := func(action, cidr string) {
		rules = append(rules, policyRule{Action: action, CIDR: cidr, Protocol: "tcp", Ports: "53"}, policyRule{Action: action, CIDR: cidr, Protocol: "udp", Ports: "53"})
	}
	appendDNS("allow", "10.0.2.3/32")
	for _, prefix := range p.excluded {
		rules = append(rules, policyRule{Action: "deny", CIDR: prefix.String()})
	}
	for _, addr := range p.dns {
		appendDNS("allow", netip.PrefixFrom(addr, 32).String())
	}
	appendDNS("deny", "")
	rules = append(rules, policyRule{Action: "deny", Protocol: "udp", Ports: "3544"},
		policyRule{Action: "allow", CIDR: "0.0.0.0/0", Protocol: "tcp"}, policyRule{Action: "allow", CIDR: "0.0.0.0/0", Protocol: "udp"})
	var err error
	p.policy, err = json.Marshal(natPolicy{Egress: policyDirection{Default: "deny", Rules: rules}, Ingress: policyDirection{Default: "deny"}})
	if err != nil || len(p.policy) > maxPolicyBytes {
		return p, errors.New("approved NAT policy exceeds GVX encoding bounds")
	}
	sum := sha256.Sum256(p.policy)
	p.digest = hex.EncodeToString(sum[:])
	return p, nil
}

// NetworkPolicyDigest validates and compiles the same profile as PlanRun
// without launch paths or reservations. Its digest omits QoS and must be
// reviewed alongside the two approved bit/s rates. NONE returns an empty digest.
func NetworkPolicyDigest(grant NetworkGrant) (string, error) {
	network, err := planNetwork(grant)
	return network.digest, err
}

func normalizePrefix(p netip.Prefix) (netip.Prefix, error) {
	if !p.IsValid() {
		return netip.Prefix{}, errors.New("invalid excluded NAT prefix")
	}
	if a := p.Addr(); a.Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, errors.New("IPv4-mapped NAT exclusion is shorter than /96")
		}
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}

func (p plannedNetwork) blocks(addr netip.Addr) bool {
	for _, exclusion := range p.excluded {
		if exclusion.Contains(addr) {
			return true
		}
	}
	return false
}

// HostIPv4Exclusions captures the installed host's IPv4 interface addresses,
// including public addresses, for inclusion in the reviewed Excluded list.
// It does not discover operator NAT aliases or the ultimate route behind a proxy.
func HostIPv4Exclusions() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, addr := range addrs {
		host, _, _ := strings.Cut(addr.String(), "/")
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return nil, fmt.Errorf("parse host interface address: %w", err)
		}
		if ip = ip.Unmap(); ip.Is4() {
			out = append(out, netip.PrefixFrom(ip, 32))
		}
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return slices.Compact(out), nil
}

func (p plannedNetwork) verifyHostExclusions() error {
	host, err := HostIPv4Exclusions()
	if err != nil {
		return err
	}
	for _, entry := range host {
		if !p.blocks(entry.Addr()) {
			return fmt.Errorf("%w: live host address %s is absent from approved NAT exclusions", ErrApprovalMismatch, entry.Addr())
		}
	}
	return nil
}
