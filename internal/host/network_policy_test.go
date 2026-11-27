//go:build linux

package host

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type networkTestPacket struct {
	in, out, src, dst, mac, protocol, state string
	port                                    int
	local                                   bool
}

// Evaluate the supported match semantics against concrete packets, rather than
// asserting a rendered command happens to contain a required substring.
func networkTestVerdict(t *testing.T, rules [][]string, p networkTestPacket) string {
	t.Helper()
	for _, rule := range rules {
		match, negate := true, false
		for i := 0; i < len(rule); i++ {
			k := rule[i]
			if k == "!" {
				negate = true
				continue
			}
			if k == "-j" {
				if match {
					return rule[i+1]
				}
				break
			}
			if i+1 >= len(rule) {
				t.Fatal("incomplete rule")
			}
			i++
			v := rule[i]
			ok := true
			switch k {
			case "-m":
				continue
			case "-i":
				ok = p.in == v
			case "-o":
				ok = p.out == v
			case "-s", "-d":
				a := p.src
				if k == "-d" {
					a = p.dst
				}
				prefix, e := parseAddressPrefix(v)
				if e != nil {
					t.Fatal(e)
				}
				ok = prefix.Contains(netip.MustParseAddr(a))
			case "-p":
				ok = p.protocol == v
			case "--mac-source":
				ok = p.mac == v
			case "--dport":
				port, e := strconv.Atoi(v)
				if e != nil {
					t.Fatal(e)
				}
				ok = p.port == port
			case "--dst-type":
				ok = p.local && v == "LOCAL"
			case "--ctstate":
				ok = slices.Contains(strings.Split(v, ","), p.state)
			default:
				t.Fatalf("unsupported policy matcher %s", k)
			}
			if negate {
				ok = !ok
				negate = false
			}
			match = match && ok
		}
	}
	return "NO_VERDICT"
}
func TestGvxNetworkPeerExclusionsAndFixedFamilies(t *testing.T) {
	r := NetworkRecord{HostInterface: "cth1", PeerIPv4: "10.240.0.2", PeerIPv6: "fd42::2", Uplink4: "eth0", Uplink6: "eth0", PeerMAC: "02:00:00:00:00:02"}
	blocked := append(append([]netip.Prefix{}, specialPurposePrefixes...), netip.MustParsePrefix("8.8.4.4/32"))
	resolvers := []string{"1.1.1.1", "2606:4700:4700::1111"}
	for _, tc := range []struct {
		name   string
		family int
		packet networkTestPacket
		want   string
	}{
		{"public outbound private allocated source", 4, networkTestPacket{"cth1", "eth0", "10.240.0.2", "8.8.8.8", r.PeerMAC, "tcp", "NEW", 443, false}, "ACCEPT"},
		{"public tracked return to private endpoint", 4, networkTestPacket{"eth0", "cth1", "8.8.8.8", "10.240.0.2", "", "tcp", "ESTABLISHED", 40000, false}, "ACCEPT"},
		{"excluded reply before established", 4, networkTestPacket{"eth0", "cth1", "10.0.0.1", "10.240.0.2", "", "tcp", "ESTABLISHED", 40000, false}, "DROP"},
		{"host public identity before established", 4, networkTestPacket{"eth0", "cth1", "8.8.4.4", "10.240.0.2", "", "tcp", "ESTABLISHED", 40000, false}, "DROP"},
		{"dns permitted resolver", 4, networkTestPacket{"cth1", "eth0", "10.240.0.2", "1.1.1.1", r.PeerMAC, "udp", "NEW", 53, false}, "ACCEPT"},
		{"dns unapproved resolver", 4, networkTestPacket{"cth1", "eth0", "10.240.0.2", "8.8.8.8", r.PeerMAC, "udp", "NEW", 53, false}, "DROP"},
		{"source spoofing", 4, networkTestPacket{"cth1", "eth0", "10.240.0.3", "8.8.8.8", r.PeerMAC, "tcp", "NEW", 443, false}, "DROP"},
		{"mac spoofing", 4, networkTestPacket{"cth1", "eth0", "10.240.0.2", "8.8.8.8", "02:ff:ff:ff:ff:ff", "tcp", "NEW", 443, false}, "DROP"},
		{"wrong uplink", 4, networkTestPacket{"cth1", "eth1", "10.240.0.2", "8.8.8.8", r.PeerMAC, "tcp", "NEW", 443, false}, "DROP"},
		{"unsolicited public ingress", 4, networkTestPacket{"eth0", "cth1", "8.8.8.8", "10.240.0.2", "", "tcp", "NEW", 40000, false}, "DROP"},
		{"public dual return to ULA endpoint", 6, networkTestPacket{"eth0", "cth1", "2606:4700:4700::1111", "fd42::2", "", "tcp", "ESTABLISHED", 40000, false}, "ACCEPT"},
		{"ULA external reply denied", 6, networkTestPacket{"eth0", "cth1", "fd43::1", "fd42::2", "", "tcp", "ESTABLISHED", 40000, false}, "DROP"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := networkForwardRules(r, tc.family, blocked, resolvers, true)
			if got := networkTestVerdict(t, rules, tc.packet); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
	r.PeerIPv6 = ""
	p := networkTestPacket{in: "cth1", out: "eth0", src: "fd42::2", dst: "2606:4700:4700::1111", mac: r.PeerMAC, protocol: "tcp", state: "NEW", port: 443}
	if got := networkTestVerdict(t, networkForwardRules(r, 6, blocked, resolvers, true), p); got != "DROP" {
		t.Fatal("v4 topology acquired IPv6 authority")
	}
	if got := networkTestVerdict(t, networkForwardRules(r, 4, blocked, resolvers, false), p); got != "DROP" {
		t.Fatal("closed generation granted traffic")
	}
}
func TestGvxNetworkIPAMCollisionAndExhaustion(t *testing.T) {
	for _, tc := range []struct {
		pool, occupied, want string
		bits                 int
	}{{"10.240.0.0/28", "10.240.0.0/30", "10.240.0.4/30", 30}, {"fd42::/124", "fd42::/126", "fd42::4/126", 126}} {
		p, e := networkChoosePrefix(netip.MustParsePrefix(tc.pool), tc.bits, []netip.Prefix{netip.MustParsePrefix(tc.occupied)})
		if e != nil || p.String() != tc.want {
			t.Fatalf("allocation=%s error=%v", p, e)
		}
		if _, e = networkChoosePrefix(netip.MustParsePrefix(tc.pool), tc.bits, []netip.Prefix{netip.MustParsePrefix(tc.pool)}); e == nil {
			t.Fatal("overlapping host route or allocation accepted")
		}
	}
}
func TestGvxNetworkRouteNotificationLoss(t *testing.T) {
	message := make([]byte, unix.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(message, uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:], unix.RTM_NEWADDR)
	if e := routeNotificationError(message, 0); e != nil {
		t.Fatal(e)
	}
	for _, raw := range [][]byte{nil, message[:7], append(append([]byte{}, message...), 1)} {
		if routeNotificationError(raw, 0) == nil {
			t.Fatal("truncated notification accepted")
		}
	}
	if routeNotificationError(message, unix.MSG_TRUNC) == nil {
		t.Fatal("notification loss accepted")
	}
	binary.NativeEndian.PutUint16(message[4:], unix.NLMSG_OVERRUN)
	if routeNotificationError(message, 0) == nil {
		t.Fatal("overrun accepted")
	}
}
func TestGvxNetworkStaticRouteAndInventoryBinding(t *testing.T) {
	r := NetworkRecord{Profile: NetworkPublicV4, IPv4Prefix: "10.240.0.0/30", HostIPv4: "10.240.0.1", PeerIPv4: "10.240.0.2", HostInterface: "cth1", PeerInterface: "ctp1"}
	routes := []networkRoute{{Dst: "10.240.0.0/30", Dev: "ctp1"}, {Dst: "default", Dev: "ctp1", Gateway: "10.240.0.1"}, {Dst: "127.0.0.0/8", Dev: "lo", Type: "local"}}
	if e := networkValidateRoutes(r, true, "-4", routes); e != nil {
		t.Fatal(e)
	}
	wrong := append([]networkRoute{}, routes...)
	wrong[1].Gateway = "10.240.0.3"
	if networkValidateRoutes(r, true, "-4", wrong) == nil {
		t.Fatal("wrong peer next hop accepted")
	}
	wrong = append(append([]networkRoute{}, routes...), networkRoute{Dst: "8.8.8.8", Dev: "ctp1"})
	if networkValidateRoutes(r, true, "-4", wrong) == nil {
		t.Fatal("foreign endpoint route accepted")
	}
	if networkValidateRoutes(r, true, "-6", []networkRoute{{Dst: "default", Dev: "ctp1", Gateway: "fd42::1"}}) == nil {
		t.Fatal("v4 topology acquired IPv6 default")
	}
	allocation := &networkAllocation{BootID: "boot-a", Record: NetworkRecord{Generation: "generation-a"}, HostInventoryDigest: "inventory-a", Rules: map[string]string{"family": "closed"}, Topology: map[string]string{"neighbor": "permanent"}, Flows: map[string]string{"tuple": "ABSENT"}}
	before, e := networkObservationDigest(allocation)
	if e != nil {
		t.Fatal(e)
	}
	allocation.Topology["neighbor"] = "changed"
	after, e := networkObservationDigest(allocation)
	if e != nil {
		t.Fatal(e)
	}
	if before == after {
		t.Fatal("neighbor drift does not change durable observation binding")
	}
	pool := netip.MustParsePrefix("10.0.0.0/8")
	prefix, e := networkChoosePrefix(pool, 30, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/9")})
	if e != nil || prefix.String() != "10.128.0.0/30" {
		t.Fatalf("large collision skip=%s error=%v", prefix, e)
	}
}
func TestGvxNetworkFixedProfileAdmission(t *testing.T) {
	if err := validateNetworkConfig(NetworkConfig{Profile: NetworkNone}); err != nil {
		t.Fatalf("NONE unexpectedly needs host routes or IPAM: %v", err)
	}
	config := NetworkConfig{Profile: NetworkPublicV4, IPv4Pool: "10.240.0.0/16", Resolvers: []string{"1.1.1.1"}, HostPublicAddresses: []string{"8.8.4.4"}, MetadataPrefixes: []string{"169.254.0.0/16"}, InventoryRevision: "approved-v1", Uplink4: "eth0", Source4: "192.168.1.10"}
	if err := validateNetworkConfig(config); err != nil {
		t.Fatal(err)
	}
	config.Profile = NetworkPublicDual
	config.IPv6Pool = "fd42::/64"
	config.Uplink6 = "eth0"
	config.Source6 = "2001:4860::1"
	if validateNetworkConfig(config) == nil {
		t.Fatal("dual profile silently accepted IPv4-only resolver inventory")
	}
	config.Resolvers = append(config.Resolvers, "2606:4700:4700::1111")
	if err := validateNetworkConfig(config); err != nil {
		t.Fatal(err)
	}
	config.Profile = NetworkPublicV4
	if validateNetworkConfig(config) == nil {
		t.Fatal("v4 profile accepted IPv6 resolver authority")
	}
}
func TestGvxNetworkPrerequisiteSemanticIdentityAcrossBoot(t *testing.T) {
	cfg := NetworkConfig{Profile: NetworkPublicV4, Uplink4: "eth0", Source4: "192.168.1.10"}
	scalar := func(value uint32) []byte {
		raw := make([]byte, 4)
		binary.NativeEndian.PutUint32(raw, value)
		return raw
	}
	attr := func(kind uint16, value []byte) networkReadAttribute {
		return networkReadAttribute{Type: kind, Value: value}
	}
	info := func(timer uint32) []byte {
		raw := make([]byte, 20)
		binary.NativeEndian.PutUint16(raw[:2], 9)
		binary.NativeEndian.PutUint16(raw[2:4], 1)
		copy(raw[4:], "veth\x00")
		binary.NativeEndian.PutUint16(raw[12:14], 8)
		binary.NativeEndian.PutUint16(raw[14:16], 2)
		copy(raw[16:], scalar(timer))
		return raw
	}
	fixture := func(index, counter uint32) networkReadInventory {
		linkHeader := make([]byte, unix.SizeofIfInfomsg)
		binary.NativeEndian.PutUint32(linkHeader[4:8], index)
		binary.NativeEndian.PutUint32(linkHeader[8:12], unix.IFF_UP)
		addressHeader := make([]byte, unix.SizeofIfAddrmsg)
		addressHeader[0] = unix.AF_INET
		addressHeader[1] = 24
		binary.NativeEndian.PutUint32(addressHeader[4:8], index)
		routeHeader := make([]byte, unix.SizeofRtMsg)
		routeHeader[0] = unix.AF_INET
		routeHeader[7] = unix.RTN_UNICAST
		binary.NativeEndian.PutUint32(routeHeader[8:12], counter)
		return networkReadInventory{
			Forwarding: []networkReadScalar{{"/proc/sys/net/ipv4/ip_forward", "1"}},
			Links:      []networkReadRow{{Header: linkHeader, Attributes: []networkReadAttribute{attr(unix.IFLA_IFNAME, []byte("eth0\x00")), attr(unix.IFLA_ADDRESS, []byte{2, 0, 0, 0, 0, 1}), attr(unix.IFLA_MTU, scalar(1500)), attr(unix.IFLA_LINKINFO, info(counter)), attr(unix.IFLA_STATS64, scalar(counter)), attr(unix.IFLA_LINK_NETNSID, scalar(counter))}}},
			Addresses:  []networkReadRow{{Header: addressHeader, Attributes: []networkReadAttribute{attr(unix.IFA_LOCAL, netip.MustParseAddr(cfg.Source4).AsSlice()), attr(unix.IFA_CACHEINFO, scalar(counter))}}},
			Selections: []networkReadSelection{{Family: "ipv4", Source: cfg.Source4, Target: "1.1.1.1", Route: networkReadRow{Header: routeHeader, Attributes: []networkReadAttribute{attr(unix.RTA_OIF, scalar(index)), attr(unix.RTA_GATEWAY, netip.MustParseAddr("192.168.1.1").AsSlice()), attr(unix.RTA_PREFSRC, netip.MustParseAddr(cfg.Source4).AsSlice()), attr(unix.RTA_CACHEINFO, scalar(counter)), attr(unix.RTA_EXPIRES, scalar(counter))}}}},
		}
	}
	project := func(raw networkReadInventory) []byte {
		view, err := networkSemanticInventory(cfg, raw)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(view)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	before := project(fixture(7, 100))
	after := project(fixture(91, 3))
	if !bytes.Equal(before, after) {
		t.Fatalf("volatile native identities/timers changed approved semantics:\n%s\n%s", before, after)
	}
	changed := fixture(91, 3)
	changed.Selections[0].Route.Attributes[1] = attr(unix.RTA_GATEWAY, netip.MustParseAddr("192.168.1.254").AsSlice())
	if bytes.Equal(before, project(changed)) {
		t.Fatal("actual effective gateway change did not invalidate approval")
	}
	first, err := networkPolicyDigest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RunRoot = "/run/different-boot"
	cfg.OperationTimeout = time.Minute
	second, err := networkPolicyDigest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("operational roots/deadlines became network permission")
	}
	none, err := networkSemanticInventory(NetworkConfig{Profile: NetworkNone}, fixture(123, 456))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(none)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"profile":"NONE","forwarding":[],"interfaces":[],"addresses":[],"routes":[]}` {
		t.Fatalf("NONE published public or diagnostic prerequisites: %s", encoded)
	}
}

func TestGvxNetworkReconciliationCannotAdmit(t *testing.T) {
	n := &Network{reconciliationOnly: true, ready: make(chan struct{}), routeFD: -1, firewallFD: -1}
	ctx := context.Background()
	if _, err := n.Prepare(ctx, Lease{}); err == nil {
		t.Fatal("cleanup-only network prepared a new instance")
	}
	if err := n.VerifyClosed(ctx, Ownership{}); err == nil {
		t.Fatal("cleanup-only network authorized stage admission")
	}
	if err := n.SetEgress(ctx, Ownership{}, EgressPublicInternet); err == nil {
		t.Fatal("cleanup-only network granted PUBLIC")
	}
	if err := n.Monitor(ctx, nil); err == nil {
		t.Fatal("cleanup-only network installed an admission monitor")
	}
	select {
	case <-n.Ready():
		t.Fatal("cleanup-only network became admission-ready")
	default:
	}
}

func TestGvxNetworkAnchorApprovalIdentity(t *testing.T) {
	actual := NetworkAnchorObject{Path: NetworkIPAMRoot, Exists: true, Properties: ProvisionProperties{Path: NetworkIPAMRoot, Mode: 0700, Dev: 1, Ino: 2}}
	expected := actual
	expected.Properties.ProductCreated = true
	if !networkAnchorEqual(actual, expected) {
		t.Fatal("truthful creation history changed native object equality")
	}
	expected.Properties.Ino = 3
	if networkAnchorEqual(actual, expected) {
		t.Fatal("changed anchor inode accepted")
	}
	expected = actual
	expected.Properties.TransportPipes = []string{"pipe:unapproved"}
	if networkAnchorEqual(actual, expected) {
		t.Fatal("unrelated compound properties entered anchor approval")
	}
}
