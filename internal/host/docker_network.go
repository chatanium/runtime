package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"golang.org/x/sys/unix"
)

type NetworkConfig struct {
	Backend             string   `json:"backend"`
	IPTables            string   `json:"iptables"`
	IP6Tables           string   `json:"ip6tables"`
	IPTablesRestore     string   `json:"iptables_restore"`
	IP6TablesRestore    string   `json:"ip6tables_restore"`
	Conntrack           string   `json:"conntrack"`
	IPv4Pool            string   `json:"ipv4_pool"`
	IPv6Pool            string   `json:"ipv6_pool"`
	Resolvers           []string `json:"resolvers"`
	HostPublicAddresses []string `json:"host_public_addresses"`
	InternalPrefixes    []string `json:"internal_prefixes"`
	MetadataPrefixes    []string `json:"metadata_prefixes"`
	// Deployment inventory must explicitly include externally NAT-mapped host IPs.
	InventoryRevision string `json:"inventory_revision"`
}
type networkPolicy struct {
	mu           sync.Mutex
	docker       *client.Client
	cfg          NetworkConfig
	timeout      time.Duration
	owned        map[string]*ownedNetwork
	watcher      *os.File
	watchStarted bool
	watchErr     error
	creates      CreateJournal
}
type ownedNetwork struct {
	owner                                            Ownership
	id, name, bridge, chain                          string
	ipv4, ipv6, gateway6, linkLocal6, hostLinkLocal6 netip.Addr
	enabled                                          bool
	policyInstalled                                  bool
	fingerprints                                     map[string][32]byte
}

func newNetworkPolicy(cli *client.Client, cfg NetworkConfig, timeout time.Duration) (*networkPolicy, error) {
	if cfg.Backend != "iptables" || cfg.InventoryRevision == "" || len(cfg.Resolvers) == 0 || len(cfg.HostPublicAddresses) == 0 || len(cfg.MetadataPrefixes) == 0 {
		return nil, invalid("explicit iptables IPv4/IPv6 resolver and infrastructure inventory required")
	}
	for _, path := range []string{cfg.IPTables, cfg.IP6Tables, cfg.IPTablesRestore, cfg.IP6TablesRestore, cfg.Conntrack} {
		if !filepath.IsAbs(path) {
			return nil, invalid("absolute trusted firewall executables required")
		}
	}
	v4, e4 := netip.ParsePrefix(cfg.IPv4Pool)
	v6, e6 := netip.ParsePrefix(cfg.IPv6Pool)
	if e4 != nil || e6 != nil || !v4.Addr().Is4() || !v6.Addr().Is6() || v4.Bits() > 28 || v6.Bits() > 120 {
		return nil, invalid("finite dedicated dual-stack network pools required")
	}
	for _, s := range append(append(append([]string{}, cfg.InternalPrefixes...), cfg.MetadataPrefixes...), cfg.HostPublicAddresses...) {
		if _, err := parseAddressPrefix(s); err != nil {
			return nil, invalid("invalid infrastructure address inventory")
		}
	}
	for _, s := range cfg.Resolvers {
		a, err := netip.ParseAddr(s)
		if err != nil || !isPublicDestination(a) {
			return nil, invalid("resolver must be an explicit public IP")
		}
	}
	return &networkPolicy{docker: cli, cfg: cfg, timeout: timeout, owned: make(map[string]*ownedNetwork)}, nil
}
func (p *networkPolicy) preflight(ctx context.Context) error {
	for _, name := range []string{"/proc/sys/net/bridge/bridge-nf-call-iptables", "/proc/sys/net/bridge/bridge-nf-call-ip6tables", "/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		b, err := os.ReadFile(name)
		if err != nil || strings.TrimSpace(string(b)) != "1" {
			return prerequisite(errors.New("dual-stack bridge packet filtering/forwarding unavailable"))
		}
	}
	for _, bin := range []string{p.cfg.IPTables, p.cfg.IP6Tables} {
		out, err := boundedCommand(ctx, bin, []string{"--version"}, nil, 4096)
		if err != nil || !strings.Contains(string(out), "nf_tables") {
			return prerequisite(errors.New("supported iptables-nft backend required"))
		}
		if _, err := boundedCommand(ctx, bin, []string{"-w", "-t", "filter", "-S", "DOCKER-USER"}, nil, 65536); err != nil {
			return prerequisite(errors.New("Docker dual-stack iptables forwarding hooks unavailable"))
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.watchErr != nil {
		return prerequisite(p.watchErr)
	}
	if !p.watchStarted {
		fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
		if err != nil {
			return err
		}
		if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR | unix.RTMGRP_LINK | unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE}); err != nil {
			unix.Close(fd)
			return err
		}
		p.watcher = os.NewFile(uintptr(fd), "flexmodule-route-monitor")
		p.watchStarted = true
		go p.watchHostAddresses(p.watcher)
	}
	for _, n := range p.owned {
		// An unresolved network-only create cannot have started an entrypoint.
		if n.owner.ContainerID == "" {
			continue
		}
		if err := p.checkIntegrityLocked(ctx, n); err != nil {
			return prerequisite(err)
		}
	}
	return nil
}
func (p *networkPolicy) resolverFile(dir string) (string, error) {
	name := filepath.Join(dir, "resolv.conf")
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
	if err != nil {
		return "", err
	}
	for _, ip := range p.cfg.Resolvers {
		if _, err := fmt.Fprintf(f, "nameserver %s\n", ip); err != nil {
			f.Close()
			return "", err
		}
	}
	// Creation permissions are filtered by the supervisor's umask. The
	// root-owned file is mounted for a different, unprivileged guest UID.
	if err := f.Chmod(0444); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	return name, f.Close()
}
func (p *networkPolicy) prepare(ctx context.Context, o Ownership) (*ownedNetwork, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n, subnet4, subnet6 := p.networkIdentity(o)
	if p.creates == nil {
		return nil, prerequisite(errors.New("durable Docker create journal is not bound"))
	}
	// Each instance gets a separate bridge and subnet. Collisions are rejected by
	// Docker IPAM, never resolved by attaching to another instance's network.
	v4 := true
	v6 := true
	if err := p.creates.SubmitCreate(ctx, o, CreateNetwork, n.name); err != nil {
		return nil, err
	}
	p.owned[o.InstanceID] = n
	request, receipt := createRequest(ctx, CreateNetwork, n.name)
	result, err := p.docker.NetworkCreate(request, n.name, client.NetworkCreateOptions{Driver: "bridge", EnableIPv4: &v4, EnableIPv6: &v6, Options: map[string]string{"com.docker.network.bridge.name": n.bridge, "com.docker.network.bridge.enable_icc": "false"}, Labels: ownershipLabels(o), IPAM: &network.IPAM{Driver: "default", Config: []network.IPAMConfig{{Subnet: subnet4, Gateway: subnet4.Addr().Next()}, {Subnet: subnet6, Gateway: subnet6.Addr().Next()}}}})
	if err != nil {
		return n, recordCreateRejection(err, receipt, p.creates, o, p.timeout)
	}
	n.id = result.ID
	created, err := p.docker.NetworkInspect(ctx, n.id, client.NetworkInspectOptions{})
	if err != nil {
		return n, err
	}
	if created.Network.ID != n.id {
		return n, errors.New("created network ID mismatch")
	}
	for key, value := range ownershipLabels(o) {
		if created.Network.Labels[key] != value {
			return n, errors.New("created network ownership mismatch")
		}
	}
	if err := p.creates.ObserveCreated(ctx, o, CreateNetwork, n.name, n.id); err != nil {
		return n, err
	}
	if err := n.refreshBridgeIPv6Identity(); err != nil {
		return n, err
	}
	n.policyInstalled = true
	if err := p.installHooks(ctx, n); err != nil {
		return n, err
	}
	return n, nil
}
func (n *ownedNetwork) refreshBridgeIPv6Identity() error {
	iface, err := net.InterfaceByName(n.bridge)
	if err != nil {
		return err
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return err
	}
	return n.setBridgeIPv6Identity(addresses)
}
func (n *ownedNetwork) setBridgeIPv6Identity(addresses []net.Addr) error {
	gatewayFound := false
	var linkLocal netip.Addr
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			continue
		}
		a := prefix.Addr()
		gatewayFound = gatewayFound || a == n.gateway6
		if a.Is6() && a.IsLinkLocalUnicast() && !linkLocal.IsValid() {
			linkLocal = a
		}
	}
	// An empty Docker bridge has no carrier and may not yet have a kernel
	// link-local address. Its explicitly assigned gateway is the required ND
	// identity; any link-local identity is refreshed once an endpoint joins.
	if !gatewayFound {
		return errors.New("dedicated bridge IPv6 gateway unavailable")
	}
	n.hostLinkLocal6 = linkLocal
	return nil
}
func (p *networkPolicy) bindContainer(n *ownedNetwork, o Ownership) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n.owner = o
}
func (p *networkPolicy) verifyEndpoint(ctx context.Context, n *ownedNetwork) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.verifyEndpointLocked(ctx, n)
}
func (p *networkPolicy) verifyEndpointLocked(ctx context.Context, n *ownedNetwork) error {
	inspected, err := p.docker.NetworkInspect(ctx, n.id, client.NetworkInspectOptions{})
	if err != nil {
		return err
	}
	for key, value := range ownershipLabels(n.owner) {
		if inspected.Network.Labels[key] != value {
			return errors.New("dedicated network ownership mismatch")
		}
	}
	if len(inspected.Network.Containers) != 1 {
		return errors.New("dedicated network has unexpected endpoints")
	}
	endpoint, ok := inspected.Network.Containers[n.owner.ContainerID]
	if !ok {
		return errors.New("owned endpoint unavailable")
	}
	if endpoint.IPv4Address.Addr() != n.ipv4 || endpoint.IPv6Address.Addr() != n.ipv6 {
		return errors.New("dual-stack endpoint identity mismatch")
	}
	return nil
}
func (p *networkPolicy) networkIdentity(o Ownership) (*ownedNetwork, netip.Prefix, netip.Prefix) {
	digest := sha256.Sum256([]byte(o.InstallationID + "\x00" + o.EpochID + "\x00" + o.InstanceID))
	suffix := hex.EncodeToString(digest[:6])
	pool4 := netip.MustParsePrefix(p.cfg.IPv4Pool).Masked()
	pool6 := netip.MustParsePrefix(p.cfg.IPv6Pool).Masked()
	b4 := pool4.Addr().As4()
	b6 := pool6.Addr().As16()
	for bit := pool4.Bits(); bit < 30; bit++ {
		if digest[(bit-pool4.Bits())/8]&(1<<uint((bit-pool4.Bits())%8)) != 0 {
			b4[bit/8] |= 1 << uint(7-bit%8)
		}
	}
	for bit := pool6.Bits(); bit < 120; bit++ {
		if digest[(bit-pool6.Bits())/8]&(1<<uint((bit-pool6.Bits())%8)) != 0 {
			b6[bit/8] |= 1 << uint(7-bit%8)
		}
	}
	subnet4 := netip.PrefixFrom(netip.AddrFrom4(b4), 30)
	subnet6 := netip.PrefixFrom(netip.AddrFrom16(b6), 120)
	n := &ownedNetwork{owner: o, name: containerName(o) + "-net", bridge: "fm" + suffix, chain: "FM" + suffix, ipv4: subnet4.Addr().Next().Next(), ipv6: subnet6.Addr().Next().Next(), gateway6: subnet6.Addr().Next(), linkLocal6: netip.MustParseAddr("fe80::2"), fingerprints: make(map[string][32]byte)}
	return n, subnet4, subnet6
}

// Every replacement marks an existing terminal rule. Even a zero-counter
// DROP-to-DROP replacement must differ from its predecessor's rule identity;
// observers must not infer counter continuity across a flush/rebuild.
func newPolicyGeneration() string { return "fm-generation:" + rand.Text() }

func (p *networkPolicy) installHooks(ctx context.Context, n *ownedNetwork) error {
	generation := newPolicyGeneration()
	for family := range 2 {
		bin, restore := p.binaries(family)
		for _, table := range []string{"raw", "mangle", "filter"} {
			script := "*" + table + "\n:" + n.chain + " - [0:0]\n-A " + n.chain + " -m comment --comment " + generation + " -j DROP\nCOMMIT\n"
			if _, err := boundedCommand(ctx, restore, []string{"--wait", "--noflush"}, strings.NewReader(script), 4096); err != nil {
				return err
			}
		}
		ip := n.ipv4
		if family == 1 {
			ip = n.ipv6
		}
		hooks := [][]string{{"raw", "PREROUTING", "-i", n.bridge}, {"filter", "INPUT", "-i", n.bridge}, {"filter", "FORWARD", "-i", n.bridge}, {"filter", "FORWARD", "-o", n.bridge}, {"mangle", "POSTROUTING", "-s", ip.String()}}
		for _, hook := range hooks {
			args := []string{"-w", "-t", hook[0], "-I", hook[1], "1"}
			args = append(args, hook[2:]...)
			args = append(args, "-j", n.chain)
			if _, err := boundedCommand(ctx, bin, args, nil, 4096); err != nil {
				return err
			}
		}
	}
	return p.recordRulesLocked(ctx, n)
}
func (p *networkPolicy) binaries(family int) (string, string) {
	if family == 0 {
		return p.cfg.IPTables, p.cfg.IPTablesRestore
	}
	return p.cfg.IP6Tables, p.cfg.IP6TablesRestore
}
func (p *networkPolicy) enable(ctx context.Context, n *ownedNetwork) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.watchErr != nil {
		return prerequisite(p.watchErr)
	}
	if !n.policyInstalled || !n.ipv4.IsValid() || !n.ipv6.IsValid() {
		return errors.New("dual-stack default-deny endpoint not ready")
	}
	if err := p.verifyEndpointLocked(ctx, n); err != nil {
		return err
	}
	if err := p.disableLocked(ctx, n); err != nil {
		return err
	}
	if err := n.refreshBridgeIPv6Identity(); err != nil {
		return err
	}
	blocked, err := p.blockedDestinations()
	if err != nil {
		return err
	}
	for family := range 2 {
		if err := p.installRules(ctx, n, family, blocked, true); err != nil {
			p.disableLocked(ctx, n)
			return err
		}
	}
	n.enabled = true
	return nil
}
func (p *networkPolicy) disable(ctx context.Context, n *ownedNetwork) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.disableLocked(ctx, n)
}
func (p *networkPolicy) disableLocked(ctx context.Context, n *ownedNetwork) error {
	var errs []error
	generation := newPolicyGeneration()
	for family := range 2 {
		_, restore := p.binaries(family)
		var script strings.Builder
		for _, table := range []string{"raw", "mangle", "filter"} {
			fmt.Fprintf(&script, "*%s\n-F %s\n-A %s -m comment --comment %s -j DROP\nCOMMIT\n", table, n.chain, n.chain, generation)
		}
		_, err := boundedCommand(ctx, restore, []string{"--wait", "--noflush"}, strings.NewReader(script.String()), 4096)
		errs = append(errs, err)
	}
	n.enabled = false
	for _, ip := range []netip.Addr{n.ipv4, n.ipv6} {
		if !ip.IsValid() {
			continue
		}
		family := "ipv4"
		if ip.Is6() {
			family = "ipv6"
		}
		for _, direction := range []string{"-s", "-d"} {
			out, err := boundedCommand(ctx, p.cfg.Conntrack, []string{"-D", "-f", family, direction, ip.String()}, nil, 4096)
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 1 || !bytes.Contains(out, []byte("0 flow entries")) {
					errs = append(errs, err)
				}
			}
		}
	}
	if errors.Join(errs...) == nil {
		errs = append(errs, p.recordRulesLocked(ctx, n))
	}
	return errors.Join(errs...)
}
func (p *networkPolicy) installRules(ctx context.Context, n *ownedNetwork, family int, blocked []netip.Prefix, enabled bool) error {
	_, restore := p.binaries(family)
	ip := n.ipv4
	if family == 1 {
		ip = n.ipv6
	}
	generation := newPolicyGeneration()
	var script strings.Builder
	for _, table := range []string{"raw", "mangle", "filter"} {
		fmt.Fprintf(&script, "*%s\n-F %s\n", table, n.chain)
		add := func(rule string) { fmt.Fprintf(&script, "-A %s %s\n", n.chain, rule) }
		// IPv6 needs narrow neighbor discovery to its own dedicated gateway. This
		// is not host application ingress: only NS/NA, hop-limit 255, exact guest
		// source and gateway/solicited-node destinations are permitted.
		if family == 1 && enabled && (table == "raw" || table == "filter") {
			target := "RETURN"
			if table == "filter" {
				target = "ACCEPT"
			}
			for _, source := range []netip.Addr{n.ipv6, n.linkLocal6} {
				for _, gateway := range []netip.Addr{n.gateway6, n.hostLinkLocal6} {
					if !gateway.IsValid() {
						continue
					}
					b := gateway.As16()
					solicited := [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, b[13], b[14], b[15]}
					add("-i " + n.bridge + " -s " + source.String() + " -d " + netip.AddrFrom16(solicited).String() + " -p ipv6-icmp --icmpv6-type 135 -m hl --hl-eq 255 -j " + target)
					for _, kind := range []string{"135", "136"} {
						add("-i " + n.bridge + " -s " + source.String() + " -d " + gateway.String() + " -p ipv6-icmp --icmpv6-type " + kind + " -m hl --hl-eq 255 -j " + target)
					}
				}
			}
		}
		if table == "raw" {
			add("! -s " + ip.String() + " -j DROP")
		}
		if table == "filter" {
			// INPUT is always denied, even for established flows to a host public IP.
			add("-m addrtype --dst-type LOCAL -j DROP")
			add("-i " + n.bridge + " -o " + n.bridge + " -j DROP")
			add("-i " + n.bridge + " ! -s " + ip.String() + " -j DROP")
			// Ingress accepts only replies to this endpoint, never new connections.
			for _, prefix := range blocked {
				if prefix.Addr().Is6() == (family == 1) {
					add("-o " + n.bridge + " -s " + prefix.String() + " -j DROP")
				}
			}
			add("-o " + n.bridge + " -d " + ip.String() + " -m conntrack --ctstate ESTABLISHED -j RETURN")
			add("-o " + n.bridge + " -j DROP")
		}
		for _, prefix := range blocked {
			if prefix.Addr().Is6() == (family == 1) {
				add("-d " + prefix.String() + " -j DROP")
			}
		}
		add("-m addrtype --dst-type LOCAL -j DROP")
		// Known network-layer transition/tunnel mechanisms must not turn an outer
		// public destination into a bypass for a blocked inner address family.
		for _, protocol := range []string{"4", "41", "47"} {
			add("-p " + protocol + " -j DROP")
		}
		add("-p udp --dport 3544 -j DROP")
		if family == 1 {
			add("! -d 2000::/3 -j DROP")
		}
		for _, protocol := range []string{"udp", "tcp"} {
			for _, resolver := range p.cfg.Resolvers {
				address := netip.MustParseAddr(resolver)
				if address.Is6() == (family == 1) {
					add("-p " + protocol + " -d " + resolver + " --dport 53 -j RETURN")
				}
			}
			add("-p " + protocol + " --dport 53 -j DROP")
		}
		if table == "filter" {
			add("-m conntrack --ctstate INVALID -j DROP")
		}
		if enabled {
			add("-m comment --comment " + generation + " -j RETURN")
		} else {
			add("-m comment --comment " + generation + " -j DROP")
		}
		script.WriteString("COMMIT\n")
	}
	if _, err := boundedCommand(ctx, restore, []string{"--wait", "--noflush"}, strings.NewReader(script.String()), 4096); err != nil {
		return err
	}
	return p.recordFamilyRulesLocked(ctx, n, family)
}
func (p *networkPolicy) blockedDestinations() ([]netip.Prefix, error) {
	out := append([]netip.Prefix{}, specialPurposePrefixes...)
	out = append(out, netip.MustParsePrefix(p.cfg.IPv4Pool), netip.MustParsePrefix(p.cfg.IPv6Pool))
	for _, s := range append(append(append([]string{}, p.cfg.InternalPrefixes...), p.cfg.MetadataPrefixes...), p.cfg.HostPublicAddresses...) {
		prefix, err := parseAddressPrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, prefix)
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addresses {
		prefix, err := netip.ParsePrefix(a.String())
		if err != nil {
			return nil, err
		}
		out = append(out, netip.PrefixFrom(prefix.Addr(), prefix.Addr().BitLen()))
	}
	return out, nil
}
func (p *networkPolicy) revokeForCleanup(ctx context.Context, o Ownership) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	n, live := p.owned[o.InstanceID]
	if !live {
		n, _, _ = p.networkIdentity(o)
	}
	n.enabled = false
	found := false
	var errs []error
	generation := ""
	for family := range 2 {
		bin, restore := p.binaries(family)
		for _, table := range []string{"raw", "mangle", "filter"} {
			exists, err := p.chainExists(ctx, bin, table, n.chain)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if !exists {
				continue
			}
			found = true
			if generation == "" {
				generation = newPolicyGeneration()
			}
			script := fmt.Sprintf("*%s\n-F %s\n-A %s -m comment --comment %s -j DROP\nCOMMIT\n", table, n.chain, n.chain, generation)
			_, err = boundedCommand(ctx, restore, []string{"--wait", "--noflush"}, strings.NewReader(script), 4096)
			errs = append(errs, err)
		}
	}
	if found {
		errs = append(errs, p.clearConntrack(ctx, n))
		if live && errors.Join(errs...) == nil {
			errs = append(errs, p.recordRulesLocked(ctx, n))
		}
	}
	return errors.Join(errs...)
}
func (p *networkPolicy) reconcile(ctx context.Context, o Ownership) error {
	n, _, _ := p.networkIdentity(o)
	return p.remove(ctx, n)
}
func (p *networkPolicy) chainExists(ctx context.Context, bin, table, chain string) (bool, error) {
	// Only a successful table inventory proves absence. A failed named-chain
	// lookup, including "Incompatible with this kernel", is not absence proof.
	// Propagate inventory failures rather than interpreting error text.
	out, err := boundedCommand(ctx, bin, []string{"-w", "-t", table, "-S"}, nil, 1<<20)
	if err != nil {
		return false, err
	}
	declaration := "-N " + chain
	for line := range strings.SplitSeq(string(out), "\n") {
		if line == declaration {
			return true, nil
		}
	}
	return false, nil
}
func (p *networkPolicy) remove(ctx context.Context, n *ownedNetwork) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.creates == nil {
		return prerequisite(errors.New("durable Docker create journal is not bound"))
	}
	record, found, lookupErr := p.creates.LookupCreate(ctx, n.owner, CreateNetwork)
	if lookupErr != nil {
		return lookupErr
	}
	if found && record.State == CreateObserved {
		n.id = record.ObjectID
	}
	var errs []error
	hadPolicy := false
	generation := ""
	// Close every extant owned chain, including a partially installed family.
	// Missing chains are already closed; errors retain cleanup ownership.
	for family := range 2 {
		bin, restore := p.binaries(family)
		for _, table := range []string{"raw", "mangle", "filter"} {
			exists, err := p.chainExists(ctx, bin, table, n.chain)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if !exists {
				continue
			}
			hadPolicy = true
			if generation == "" {
				generation = newPolicyGeneration()
			}
			script := fmt.Sprintf("*%s\n-F %s\n-A %s -m comment --comment %s -j DROP\nCOMMIT\n", table, n.chain, n.chain, generation)
			_, err = boundedCommand(ctx, restore, []string{"--wait", "--noflush"}, strings.NewReader(script), 4096)
			errs = append(errs, err)
		}
	}
	n.enabled = false
	id := n.id
	if id == "" {
		id = n.name
	}
	inspected, err := p.docker.NetworkInspect(ctx, id, client.NetworkInspectOptions{})
	if err == nil {
		for key, value := range ownershipLabels(n.owner) {
			if inspected.Network.Labels[key] != value {
				return errors.New("refusing unrelated network cleanup")
			}
		}
		if err := p.creates.ObserveCreated(ctx, n.owner, CreateNetwork, n.name, inspected.Network.ID); err != nil {
			return err
		}
		for containerID := range inspected.Network.Containers {
			c, err := p.docker.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
			if err != nil {
				return err
			}
			if err := verifyOwnership(c.Container, n.owner); err != nil {
				return err
			}
			if _, err := p.docker.NetworkDisconnect(ctx, id, client.NetworkDisconnectOptions{Container: containerID, Force: true}); err != nil && !errdefs.IsNotFound(err) {
				errs = append(errs, err)
			}
		}
		if _, err := p.docker.NetworkRemove(ctx, id, client.NetworkRemoveOptions{}); err != nil && !errdefs.IsNotFound(err) {
			errs = append(errs, err)
		}
	} else if !errdefs.IsNotFound(err) {
		errs = append(errs, err)
	}
	if _, err := p.docker.NetworkInspect(ctx, id, client.NetworkInspectOptions{}); err == nil {
		return errors.Join(ErrCleanupIncomplete, errors.Join(errs...))
	} else if !errdefs.IsNotFound(err) {
		return errors.Join(err, errors.Join(errs...))
	}
	if err := requireCreateResolved(ctx, p.creates, n.owner, CreateNetwork, n.name); err != nil {
		return errors.Join(err, errors.Join(errs...))
	}
	delete(p.owned, n.owner.InstanceID)
	if hadPolicy || n.id != "" {
		errs = append(errs, p.clearConntrack(ctx, n))
	}
	// Never remove the fail-closed hooks while an owned endpoint still exists.
	for family := range 2 {
		bin, _ := p.binaries(family)
		ip := n.ipv4
		if family == 1 {
			ip = n.ipv6
		}
		hooks := [][]string{{"raw", "PREROUTING", "-i", n.bridge}, {"filter", "INPUT", "-i", n.bridge}, {"filter", "FORWARD", "-i", n.bridge}, {"filter", "FORWARD", "-o", n.bridge}, {"mangle", "POSTROUTING", "-s", ip.String()}}
		for _, hook := range hooks {
			check := append([]string{"-w", "-t", hook[0], "-C", hook[1]}, hook[2:]...)
			check = append(check, "-j", n.chain)
			if _, err := boundedCommand(ctx, bin, check, nil, 4096); err != nil {
				continue
			}
			args := append([]string{"-w", "-t", hook[0], "-D", hook[1]}, hook[2:]...)
			args = append(args, "-j", n.chain)
			if _, err := boundedCommand(ctx, bin, args, nil, 4096); err != nil {
				errs = append(errs, err)
			}
		}
		for _, table := range []string{"raw", "mangle", "filter"} {
			exists, err := p.chainExists(ctx, bin, table, n.chain)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if !exists {
				continue
			}
			for _, op := range []string{"-F", "-X"} {
				if _, err := boundedCommand(ctx, bin, []string{"-w", "-t", table, op, n.chain}, nil, 4096); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	delete(p.owned, n.owner.InstanceID)
	return nil
}
func (p *networkPolicy) clearConntrack(ctx context.Context, n *ownedNetwork) error {
	var errs []error
	for _, ip := range []netip.Addr{n.ipv4, n.ipv6} {
		family := "ipv4"
		if ip.Is6() {
			family = "ipv6"
		}
		for _, direction := range []string{"-s", "-d"} {
			out, err := boundedCommand(ctx, p.cfg.Conntrack, []string{"-D", "-f", family, direction, ip.String()}, nil, 4096)
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 1 || !bytes.Contains(out, []byte("0 flow entries")) {
					errs = append(errs, err)
				}
			}
		}
	}
	return errors.Join(errs...)
}
func routeNotificationError(data []byte, flags int) error {
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return errors.New("route monitor notification truncated")
	}
	if len(data) == 0 {
		return errors.New("route monitor notification empty")
	}
	for len(data) != 0 {
		if len(data) < unix.NLMSG_HDRLEN {
			return errors.New("route monitor notification header truncated")
		}
		length := int(binary.NativeEndian.Uint32(data[:4]))
		if length < unix.NLMSG_HDRLEN || length > len(data) {
			return errors.New("route monitor notification length invalid")
		}
		kind := binary.NativeEndian.Uint16(data[4:6])
		if kind == unix.NLMSG_ERROR || kind == unix.NLMSG_OVERRUN {
			return errors.New("route monitor reported notification loss")
		}
		aligned := (length + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1)
		if length == len(data) {
			return nil
		}
		if aligned > len(data) {
			return errors.New("route monitor notification padding truncated")
		}
		data = data[aligned:]
	}
	return nil
}

func readRouteNotification(fd *os.File, buffer []byte) error {
	raw, err := fd.SyscallConn()
	if err != nil {
		return err
	}
	var n, flags int
	var receiveErr error
	if err := raw.Read(func(fd uintptr) bool {
		n, _, flags, _, receiveErr = unix.Recvmsg(int(fd), buffer, nil, unix.MSG_DONTWAIT)
		return !errors.Is(receiveErr, unix.EAGAIN) && !errors.Is(receiveErr, unix.EWOULDBLOCK)
	}); err != nil {
		return err
	}
	if receiveErr != nil {
		return receiveErr
	}
	return routeNotificationError(buffer[:n], flags)
}

func drainRouteNotifications(fd *os.File, buffer []byte) error {
	raw, err := fd.SyscallConn()
	if err != nil {
		return err
	}
	var receiveErr error
	if err := raw.Control(func(fd uintptr) {
		total := 0
		for range 256 {
			n, _, flags, _, err := unix.Recvmsg(int(fd), buffer, nil, unix.MSG_DONTWAIT)
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return
			}
			if err != nil {
				receiveErr = err
				return
			}
			if receiveErr = routeNotificationError(buffer[:n], flags); receiveErr != nil {
				return
			}
			total += n
			if total > 1<<20 {
				receiveErr = errors.New("route monitor notification byte bound exceeded")
				return
			}
		}
		receiveErr = errors.New("route monitor notification count bound exceeded")
	}); err != nil {
		return err
	}
	return receiveErr
}

func (p *networkPolicy) reconcileRouteBurstLocked(fd *os.File, buffer []byte, notificationErr error) []Ownership {
	type closedNetwork struct {
		network *ownedNetwork
		enabled bool
		ctx     context.Context
		cancel  context.CancelFunc
		err     error
	}
	closed := make([]closedNetwork, 0, len(p.owned))
	haveEnabled := false
	// Close every bound policy, even when enabled is false: a failed/partial
	// installation is not proof that all tables and both families are closed.
	for _, n := range p.owned {
		if n.owner.ContainerID == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
		state := closedNetwork{network: n, enabled: n.enabled, ctx: ctx, cancel: cancel}
		state.err = p.disableLocked(ctx, n)
		closed = append(closed, state)
		haveEnabled = haveEnabled || state.enabled
	}
	// Notifications already queued belong to the same closed reconciliation
	// interval. Draining them avoids replaying startup address/route bursts as
	// repeated conntrack deletion and full policy replacement after reopening.
	if notificationErr == nil {
		notificationErr = drainRouteNotifications(fd, buffer)
	}
	if notificationErr != nil {
		p.watchErr = notificationErr
	}
	var blocked []netip.Prefix
	var inventoryErr error
	if notificationErr == nil && haveEnabled {
		blocked, inventoryErr = p.blockedDestinations()
	}
	var kill []Ownership
	for _, state := range closed {
		n, err := state.network, state.err
		if notificationErr == nil && err == nil && state.enabled {
			err = n.refreshBridgeIPv6Identity()
			if err == nil {
				err = inventoryErr
			}
			if err == nil {
				for family := range 2 {
					if err = p.installRules(state.ctx, n, family, blocked, true); err != nil {
						break
					}
				}
				if err == nil {
					n.enabled = true
				}
			}
		}
		if notificationErr != nil || err != nil {
			p.disableLocked(state.ctx, n)
			kill = append(kill, n.owner)
		}
		state.cancel()
	}
	return kill
}

func (p *networkPolicy) watchHostAddresses(fd *os.File) {
	// Close before coalescing each finite burst, then rebuild from the complete
	// current inventory once. A later event begins a new closed interval.
	buffer := make([]byte, 65536)
	for {
		err := readRouteNotification(fd, buffer)
		p.mu.Lock()
		if p.watcher != fd {
			p.mu.Unlock()
			return
		}
		kill := p.reconcileRouteBurstLocked(fd, buffer, err)
		failed := p.watchErr != nil
		p.mu.Unlock()
		for _, o := range kill {
			ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
			p.docker.ContainerKill(ctx, o.ContainerID, client.ContainerKillOptions{Signal: "SIGKILL"})
			cancel()
		}
		if failed {
			fd.Close()
			return
		}
	}
}

func (p *networkPolicy) recordFamilyRulesLocked(ctx context.Context, n *ownedNetwork, family int) error {
	bin, _ := p.binaries(family)
	for _, table := range []string{"raw", "mangle", "filter"} {
		out, err := boundedCommand(ctx, bin, []string{"-w", "-t", table, "-S", n.chain}, nil, 1<<20)
		if err != nil {
			return err
		}
		n.fingerprints[fmt.Sprintf("%d/%s", family, table)] = sha256.Sum256(out)
	}
	return nil
}
func (p *networkPolicy) recordRulesLocked(ctx context.Context, n *ownedNetwork) error {
	for family := range 2 {
		if err := p.recordFamilyRulesLocked(ctx, n, family); err != nil {
			return err
		}
	}
	return nil
}
func (p *networkPolicy) checkIntegrityLocked(ctx context.Context, n *ownedNetwork) error {
	if !n.policyInstalled {
		return errors.New("incomplete network policy allocation")
	}
	for family := range 2 {
		bin, _ := p.binaries(family)
		ip := n.ipv4
		if family == 1 {
			ip = n.ipv6
		}
		for _, table := range []string{"raw", "mangle", "filter"} {
			out, err := boundedCommand(ctx, bin, []string{"-w", "-t", table, "-S", n.chain}, nil, 1<<20)
			if err != nil {
				return err
			}
			if sha256.Sum256(out) != n.fingerprints[fmt.Sprintf("%d/%s", family, table)] {
				return errors.New("owned firewall policy changed")
			}
		}
		hooks := [][]string{{"raw", "PREROUTING", "-i", n.bridge}, {"filter", "INPUT", "-i", n.bridge}, {"filter", "FORWARD", "-i", n.bridge}, {"filter", "FORWARD", "-o", n.bridge}, {"mangle", "POSTROUTING", "-s", ip.String()}}
		for _, hook := range hooks {
			args := append([]string{"-w", "-t", hook[0], "-C", hook[1]}, hook[2:]...)
			args = append(args, "-j", n.chain)
			if _, err := boundedCommand(ctx, bin, args, nil, 4096); err != nil {
				return errors.New("owned firewall hook missing")
			}
			out, err := boundedCommand(ctx, bin, []string{"-w", "-t", hook[0], "-S", hook[1]}, nil, 1<<20)
			if err != nil {
				return err
			}
			found := false
			for _, line := range strings.Split(string(out), "\n") {
				if !strings.HasPrefix(line, "-A ") {
					continue
				}
				if strings.Contains(line, " -j "+n.chain) && (strings.Contains(line, " "+hook[2]+" "+hook[3]+" ") || strings.Contains(line, " "+hook[2]+" "+hook[3]+"/32 ") || strings.Contains(line, " "+hook[2]+" "+hook[3]+"/128 ")) {
					found = true
					break
				}
				if !strings.Contains(line, " -j FM") {
					return errors.New("owned firewall hook no longer precedes other policy")
				}
			}
			if !found {
				return errors.New("owned firewall hook priority missing")
			}
		}
	}
	return nil
}

type boundedCommandOutput struct {
	bytes.Buffer
	limit     int
	truncated bool
}

func (b *boundedCommandOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - b.Len()
	if remaining > len(p) {
		remaining = len(p)
	}
	if remaining < len(p) {
		b.truncated = true
	}
	if remaining > 0 {
		b.Buffer.Write(p[:remaining])
	}
	return n, nil
}
func boundedCommand(ctx context.Context, path string, args []string, input io.Reader, limit int) ([]byte, error) {
	command := exec.CommandContext(ctx, path, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	command.Stdin = input
	out := &boundedCommandOutput{limit: limit}
	command.Stdout = out
	command.Stderr = out
	err := command.Run()
	if err == nil && out.truncated {
		err = errors.New("trusted command output exceeded its finite bound")
	}
	return out.Bytes(), err
}
func parseAddressPrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}
func isPublicDestination(a netip.Addr) bool {
	if !a.IsGlobalUnicast() || a.Is4In6() {
		return false
	}
	if a.Is6() && !netip.MustParsePrefix("2000::/3").Contains(a) {
		return false
	}
	for _, p := range specialPurposePrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// Conservative IANA special-purpose snapshot, 2026-10-29. Explicitly includes
// IPv4 translation/tunnel prefixes; application relaying by public peers is not
// claimed to be prevented by a packet destination policy.
var specialPurposePrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/96", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "ff00::/8"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()
