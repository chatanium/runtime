//go:build linux

package host

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
)

// The exclusion is always applied to the external peer, never to the private
// source allocated to the instance. In particular it precedes tracked replies.
func networkForwardRules(r NetworkRecord, family int, blocked []netip.Prefix, resolvers []string, enabled bool) [][]string {
	peer, uplink := r.PeerIPv4, r.Uplink4
	if family == 6 {
		peer, uplink = r.PeerIPv6, r.Uplink6
	}
	if !enabled || peer == "" {
		return [][]string{{"-j", "DROP"}}
	}
	iface := r.HostInterface
	rules := [][]string{
		{"-i", iface, "!", "-s", peer, "-j", "DROP"},
		{"-i", iface, "-m", "mac", "!", "--mac-source", r.PeerMAC, "-j", "DROP"},
		{"-o", iface, "!", "-d", peer, "-j", "DROP"},
		{"-i", iface, "!", "-o", uplink, "-j", "DROP"},
		{"-o", iface, "!", "-i", uplink, "-j", "DROP"},
		{"-m", "addrtype", "--dst-type", "LOCAL", "-j", "DROP"},
	}
	for _, p := range blocked {
		if p.Addr().Is4() != (family == 4) {
			continue
		}
		rules = append(rules, []string{"-i", iface, "-d", p.String(), "-j", "DROP"}, []string{"-o", iface, "-s", p.String(), "-j", "DROP"})
	}
	for _, protocol := range []string{"4", "41", "47"} {
		rules = append(rules, []string{"-p", protocol, "-j", "DROP"})
	}
	rules = append(rules, []string{"-p", "udp", "--dport", "3544", "-j", "DROP"})
	if family == 6 {
		rules = append(rules, []string{"-i", iface, "!", "-d", "2000::/3", "-j", "DROP"}, []string{"-o", iface, "!", "-s", "2000::/3", "-j", "DROP"})
	}
	rules = append(rules, []string{"-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"}, []string{"-i", uplink, "-o", iface, "-d", peer, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"})
	for _, protocol := range []string{"udp", "tcp"} {
		for _, resolver := range resolvers {
			a := netip.MustParseAddr(resolver)
			if a.Is4() == (family == 4) {
				rules = append(rules, []string{"-i", iface, "-s", peer, "-o", uplink, "-p", protocol, "-d", resolver, "--dport", "53", "-j", "ACCEPT"})
			}
		}
		rules = append(rules, []string{"-i", iface, "-p", protocol, "--dport", "53", "-j", "DROP"})
	}
	return append(rules, []string{"-i", iface, "-s", peer, "-o", uplink, "-j", "ACCEPT"}, []string{"-j", "DROP"})
}

func networkToken(product, generation string) string {
	d := sha256.Sum256([]byte(product + "\x00" + generation))
	return hex.EncodeToString(d[:8])
}
func networkChains(r NetworkRecord) (string, string, string) {
	t := networkToken("filter", r.Generation)
	return "CTF" + t, "CTI" + t, "CTN" + t
}
func parseAddressPrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, e := netip.ParsePrefix(s)
		return p.Masked(), e
	}
	a, e := netip.ParseAddr(s)
	if e != nil {
		return netip.Prefix{}, e
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}
func isPublicDestination(a netip.Addr) bool {
	if a.Zone() != "" || !a.IsGlobalUnicast() || a.Is4In6() || (a.Is6() && !netip.MustParsePrefix("2000::/3").Contains(a)) {
		return false
	}
	for _, p := range specialPurposePrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var specialPurposePrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/96", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "ff00::/8"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func networkChoosePrefix(pool netip.Prefix, bits int, occupied []netip.Prefix) (netip.Prefix, error) {
	if !pool.IsValid() || pool.Bits() > bits || bits != pool.Addr().BitLen()-2 {
		return netip.Prefix{}, errors.New("invalid point-to-point allocation pool")
	}
	a := pool.Masked().Addr()
	for range len(occupied) + 1 {
		if !a.IsValid() || !pool.Contains(a) {
			break
		}
		p := netip.PrefixFrom(a, bits)
		collision := false
		for _, other := range occupied {
			if !p.Overlaps(other) {
				continue
			}
			collision = true
			end := networkPrefixLast(p)
			otherEnd := networkPrefixLast(other)
			if otherEnd.Compare(end) > 0 {
				end = otherEnd
			}
			a = end.Next()
			break
		}
		if !collision {
			return p, nil
		}
	}
	return netip.Prefix{}, errors.New("nonoverlapping network pool exhausted")
}
func networkPrefixLast(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr()
	b := a.As16()
	start := p.Bits()
	if a.Is4() {
		start += 96
	}
	for bit := start; bit < 128; bit++ {
		b[bit/8] |= 1 << uint(7-bit%8)
	}
	if a.Is4() {
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	return netip.AddrFrom16(b)
}
