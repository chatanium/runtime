//go:build linux

package host

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/thirdscam/chatanium/internal/bundle"
	"golang.org/x/sys/unix"
)

type NetworkConfig struct {
	Profile             NetworkProfile `json:"profile"`
	RunRoot             string         `json:"run_root"`
	IPv4Pool            string         `json:"ipv4_pool"`
	IPv6Pool            string         `json:"ipv6_pool"`
	Resolvers           []string       `json:"resolvers"`
	HostPublicAddresses []string       `json:"host_public_addresses"`
	InternalPrefixes    []string       `json:"internal_prefixes"`
	MetadataPrefixes    []string       `json:"metadata_prefixes"`
	InventoryRevision   string         `json:"inventory_revision"`
	Uplink4             string         `json:"uplink4"`
	Uplink6             string         `json:"uplink6"`
	Source4             string         `json:"source4"`
	Source6             string         `json:"source6"`
	OperationTimeout    time.Duration  `json:"operation_timeout"`
}
type Network struct {
	mu                 sync.Mutex
	cfg                NetworkConfig
	store              *Store
	systemd            *Systemd
	product            string
	owned              map[string]*networkAllocation
	monitorReady       bool
	monitorErr         error
	monitorCancel      context.CancelFunc
	monitorDone        chan struct{}
	ready              chan struct{}
	monitorStarted     bool
	routeFD            int
	firewallFD         int
	reconciliationOnly bool
}

func NewNetwork(ctx context.Context, cfg NetworkConfig, store *Store, d *Systemd) (*Network, error) {
	return newNetwork(ctx, cfg, store, d, false)
}

// NewNetworkForReconcile opens the same network implementation without launch
// authority. It never creates boot roots, subscribes a monitor, or signals Ready.
func NewNetworkForReconcile(ctx context.Context, cfg NetworkConfig, store *Store, d *Systemd) (*Network, error) {
	return newNetwork(ctx, cfg, store, d, true)
}

func newNetwork(ctx context.Context, cfg NetworkConfig, store *Store, d *Systemd, reconciliationOnly bool) (*Network, error) {
	if store == nil || d == nil {
		return nil, invalid("network requires live store and verified systemd")
	}
	if !reconciliationOnly {
		if err := validateNetworkConfig(cfg); err != nil {
			return nil, err
		}
	} else if (cfg.Profile != NetworkNone && cfg.Profile != NetworkPublicV4 && cfg.Profile != NetworkPublicDual) || cfg.OperationTimeout < 0 || cfg.OperationTimeout > 5*time.Minute {
		return nil, invalid("invalid installed network reconciliation profile or timeout")
	}
	if cfg.OperationTimeout == 0 {
		cfg.OperationTimeout = 30 * time.Second
	}
	installation, err := store.Installation(ctx)
	if err != nil {
		return nil, err
	}
	if cfg.RunRoot != installation.Paths.RunRoot || !filepath.IsAbs(cfg.RunRoot) || filepath.Clean(cfg.RunRoot) != cfg.RunRoot || cfg.RunRoot == "/" {
		return nil, invalid("network run root must be the exact installed root")
	}
	if reconciliationOnly {
		if _, err = networkOptionalNamespaceDirectory(cfg.RunRoot); err != nil {
			return nil, prerequisite(err)
		}
	} else if err = networkTrustedDirectory(filepath.Join(cfg.RunRoot, "netns")); err != nil {
		return nil, prerequisite(err)
	}
	if err = networkHostNamespaces(); err != nil {
		return nil, err
	}
	if err = d.BindStore(store); err != nil {
		return nil, err
	}
	var allocations []*networkAllocation
	if cfg.Profile != NetworkNone {
		lock, e := networkLock(ctx)
		if e != nil {
			return nil, e
		}
		defer networkUnlock(lock)
		allocations, err = networkAllocations()
		if err != nil {
			return nil, err
		}
	}
	n := &Network{cfg: cfg, store: store, systemd: d, product: installation.RuntimeInstallationID, owned: make(map[string]*networkAllocation), routeFD: -1, firewallFD: -1, monitorDone: make(chan struct{}), ready: make(chan struct{}), reconciliationOnly: reconciliationOnly}
	for _, a := range allocations {
		if a.Owner.RuntimeInstallationID != n.product || a.Record.State == "CLEANED" {
			continue
		}
		if a.Record.NetnsPath != filepath.Join(cfg.RunRoot, "netns", "ct-"+networkToken(n.product, a.Record.Generation)) {
			return nil, prerequisite(errors.New("network namespace path differs from installed owned run root"))
		}
		durable, e := store.Network(ctx, a.Owner)
		if e != nil {
			return nil, e
		}
		if durable.Generation != a.Record.Generation || durable.BootID != a.Record.BootID || a.BootID != a.Record.BootID || durable.Profile != a.Record.Profile || durable.IPv4Prefix != a.Record.IPv4Prefix || durable.IPv6Prefix != a.Record.IPv6Prefix {
			return nil, errors.New("durable network ownership/allocation mismatch")
		}
		digest, e := networkObservationDigest(a)
		if e != nil {
			return nil, e
		}
		if a.Record.InventoryDigest != "" && digest != a.Record.InventoryDigest {
			return nil, errors.New("network observation digest mismatch")
		}
		if durable.InventoryDigest != a.Record.InventoryDigest || a.Record.State == "OPEN" || a.Record.State == "OPENING" {
			a.Record.State = "RECOVERY_REQUIRED"
		}
		n.owned[a.Owner.InstanceID] = a
	}
	if reconciliationOnly {
		return n, nil
	}
	// Subscribe before any mutation; an overrun is authority loss, not a hint to
	// silently resnapshot and preserve an existing grant.
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	groups := uint32(unix.RTMGRP_LINK|unix.RTMGRP_NEIGH|unix.RTMGRP_IPV4_IFADDR|unix.RTMGRP_IPV6_IFADDR|unix.RTMGRP_IPV4_ROUTE|unix.RTMGRP_IPV6_ROUTE|unix.RTMGRP_IPV4_RULE) | (1 << (unix.RTNLGRP_IPV6_RULE - 1))
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	n.routeFD = fd
	if cfg.Profile != NetworkNone {
		// NFNLGRP_NFTABLES is multicast group 7. This is the actual nftables event
		// channel used by the required bundled iptables-nft backend.
		nft, e := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_NETFILTER)
		if e != nil {
			unix.Close(fd)
			return nil, e
		}
		if e = unix.Bind(nft, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1 << (unix.NFNLGRP_NFTABLES - 1)}); e != nil {
			unix.Close(nft)
			unix.Close(fd)
			return nil, e
		}
		n.firewallFD = nft
	}
	return n, nil
}
func validateNetworkConfig(c NetworkConfig) error {
	if c.Profile != NetworkNone && c.Profile != NetworkPublicV4 && c.Profile != NetworkPublicDual {
		return invalid("fixed network family profile required")
	}
	if c.OperationTimeout < 0 || c.OperationTimeout > 5*time.Minute {
		return invalid("invalid bounded network operation timeout")
	}
	if c.Profile == NetworkNone {
		return nil
	}
	p, e := netip.ParsePrefix(c.IPv4Pool)
	if e != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() < 8 || p.Bits() > 30 {
		return invalid("dedicated canonical IPv4 pool required")
	}
	if c.Profile == NetworkPublicDual {
		p, e = netip.ParsePrefix(c.IPv6Pool)
		if e != nil || !netip.MustParsePrefix("fc00::/7").Contains(p.Addr()) || p != p.Masked() || p.Bits() < 48 || p.Bits() > 126 {
			return invalid("dedicated ULA pool required")
		}
	}
	if c.InventoryRevision == "" || len(c.HostPublicAddresses) == 0 || len(c.MetadataPrefixes) == 0 || len(c.Resolvers) == 0 || len(c.Resolvers) > 16 {
		return invalid("explicit finite resolver and host/infrastructure inventory required")
	}
	for _, x := range append(append(append([]string{}, c.HostPublicAddresses...), c.InternalPrefixes...), c.MetadataPrefixes...) {
		if _, e := parseAddressPrefix(x); e != nil {
			return invalid("invalid infrastructure inventory")
		}
	}
	have4, have6 := false, false
	for _, x := range c.Resolvers {
		a, e := netip.ParseAddr(x)
		if e != nil || !isPublicDestination(a) {
			return invalid("resolver must be an explicit public address")
		}
		if a.Is4() {
			have4 = true
		} else {
			have6 = true
		}
	}
	if !have4 || (c.Profile == NetworkPublicV4 && have6) || (c.Profile == NetworkPublicDual && !have6) {
		return invalid("resolver family differs from fixed profile")
	}
	for _, pair := range [][2]string{{c.Uplink4, c.Source4}, {c.Uplink6, c.Source6}} {
		if pair[0] == "" && pair[1] == "" {
			continue
		}
		if !networkInterfaceName(pair[0]) {
			return invalid("invalid uplink interface")
		}
		a, e := netip.ParseAddr(pair[1])
		if e != nil || !a.IsGlobalUnicast() || a.Is4In6() {
			return invalid("invalid selected source")
		}
	}
	if c.Uplink4 == "" || c.Source4 == "" || (c.Profile == NetworkPublicDual && (c.Uplink6 == "" || c.Source6 == "" || !isPublicDestination(netip.MustParseAddr(c.Source6)))) {
		return invalid("selected family uplink and source required")
	}
	if !netip.MustParseAddr(c.Source4).Is4() || (c.Profile == NetworkPublicDual && !netip.MustParseAddr(c.Source6).Is6()) {
		return invalid("selected source family mismatch")
	}
	return nil
}
func networkInterfaceName(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

type networkHelperExit struct {
	program string
	exit    ProcessExit
	output  []byte
}

func (e *networkHelperExit) Error() string {
	return fmt.Sprintf("network helper %s exited %d: %.4096s", e.program, e.exit.Value, e.output)
}
func (n *Network) run(ctx context.Context, program, ns string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, n.cfg.OperationTimeout)
	defer cancel()
	if ns == "" {
		ns = "/proc/1/ns/net"
	}
	out, status, err := n.systemd.RunNetwork(ctx, n.helperOwner(ns, args), bundle.ProgramID(program), ns, args)
	if err != nil {
		return out, err
	}
	if status.Kind != "exit" || status.OOMKilled {
		return out, fmt.Errorf("network helper did not exit normally: %s/%d", status.Kind, status.Value)
	}
	if status.Value != 0 {
		return out, &networkHelperExit{program, status, out}
	}
	return out, nil
}
func (n *Network) networkStatus(ctx context.Context, id bundle.ProgramID, ns string, args []string) ([]byte, ProcessExit, error) {
	bounded, cancel := context.WithTimeout(ctx, n.cfg.OperationTimeout)
	defer cancel()
	if ns == "" {
		ns = "/proc/1/ns/net"
	}
	return n.systemd.RunNetwork(bounded, n.helperOwner(ns, args), id, ns, args)
}
func (n *Network) ip(ctx context.Context, ns string, args ...string) ([]byte, error) {
	return n.run(ctx, "ip", ns, args...)
}
func (n *Network) tables(ctx context.Context, family int, ns, table string, args ...string) ([]byte, error) {
	program := "iptables"
	if family == 6 {
		program = "ip6tables"
	}
	return n.run(ctx, program, ns, append([]string{"-w", "5", "-t", table}, args...)...)
}
func (n *Network) save(ctx context.Context, a *networkAllocation) error {
	digest, err := networkObservationDigest(a)
	if err != nil {
		return err
	}
	a.Record.InventoryDigest = digest
	if a.Record.Profile == NetworkNone {
		return n.store.RecordNetwork(ctx, a.Owner, a.Record)
	}
	if err = networkSave(a); err != nil {
		return err
	}
	if a.Record.State == "CLEANED" {
		if err = os.Remove(networkAllocationPath(a)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err = networkSyncDirectory(); err != nil {
			return err
		}
	}
	return n.store.RecordNetwork(ctx, a.Owner, a.Record)
}
func (n *Network) allocation(o Ownership) (*networkAllocation, error) {
	a := n.owned[o.InstanceID]
	if a == nil || a.Owner.RuntimeInstallationID != o.RuntimeInstallationID || a.Owner.InstallationID != o.InstallationID || a.Owner.EpochID != o.EpochID {
		return nil, errors.New("network ownership mismatch")
	}
	return a, nil
}
func (n *Network) helperOwner(ns string, args []string) Ownership {
	for _, a := range n.owned {
		r := a.Record
		if ns != "" && ns == r.NetnsPath {
			return a.Owner
		}
		f, i, nat := networkChains(r)
		for _, arg := range args {
			for _, identity := range []string{r.NetnsPath, filepath.Base(r.NetnsPath), r.HostInterface, r.PeerInterface, r.PeerIPv4, r.PeerIPv6, f, i, nat} {
				if identity != "" && arg == identity {
					return a.Owner
				}
			}
		}
	}
	return Ownership{RuntimeInstallationID: n.product}
}

func (n *Network) Prepare(ctx context.Context, l Lease) (NetworkRecord, error) {
	if n.reconciliationOnly {
		return NetworkRecord{}, invalid("reconciliation-only network cannot prepare an instance")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if l.Ownership.RuntimeInstallationID != n.product || l.NetworkGeneration == "" || (l.Topology != NetworkNone && l.Topology != n.cfg.Profile) {
		return NetworkRecord{}, invalid("network lease differs from installed topology")
	}
	if _, exists := n.owned[l.Ownership.InstanceID]; exists {
		return NetworkRecord{}, ErrCreateAlreadySubmitted
	}
	var allocations []*networkAllocation
	if l.Topology != NetworkNone {
		lock, e := networkLock(ctx)
		if e != nil {
			return NetworkRecord{}, e
		}
		defer networkUnlock(lock)
		allocations, e = networkAllocations()
		if e != nil {
			return NetworkRecord{}, e
		}
	}
	token := networkToken(n.product, l.NetworkGeneration)
	r := NetworkRecord{Generation: l.NetworkGeneration, Profile: l.Topology, NetnsPath: filepath.Join(n.cfg.RunRoot, "netns", "ct-"+token), State: "RESERVED"}
	boot, err := networkBootID()
	if err != nil {
		return r, err
	}
	r.BootID = boot
	a := &networkAllocation{Owner: l.Ownership, BootID: boot, Record: r, Rules: map[string]string{}, Topology: map[string]string{}, Flows: map[string]string{}}
	if l.Topology != NetworkNone {
		r.FilterGeneration = rand.Text()
		r.NATGeneration = rand.Text()
		r.HostInterface = "cth" + token[:11]
		r.PeerInterface = "ctp" + token[:11]
		r.HostMAC = "02:" + token[0:2] + ":" + token[2:4] + ":" + token[4:6] + ":" + token[6:8] + ":01"
		r.PeerMAC = strings.TrimSuffix(r.HostMAC, "01") + "02"
		occupied, err := n.occupied(ctx, allocations)
		if err != nil {
			return r, err
		}
		p, err := networkChoosePrefix(netip.MustParsePrefix(n.cfg.IPv4Pool), 30, occupied)
		if err != nil {
			return r, err
		}
		r.IPv4Prefix = p.String()
		r.HostIPv4 = p.Addr().Next().String()
		r.PeerIPv4 = p.Addr().Next().Next().String()
		r.Uplink4 = n.cfg.Uplink4
		r.Source4 = n.cfg.Source4
		if l.Topology == NetworkPublicDual {
			p, err = networkChoosePrefix(netip.MustParsePrefix(n.cfg.IPv6Pool), 126, occupied)
			if err != nil {
				return r, err
			}
			r.IPv6Prefix = p.String()
			r.HostIPv6 = p.Addr().Next().String()
			r.PeerIPv6 = p.Addr().Next().Next().String()
			r.Uplink6 = n.cfg.Uplink6
			r.Source6 = n.cfg.Source6
		}
		a.Record = r
		if err = n.preflight(ctx, a); err != nil {
			return r, err
		}
	}
	if _, err = os.Lstat(r.NetnsPath); err == nil {
		return r, errors.New("network namespace name collides with an existing object")
	} else if !errors.Is(err, os.ErrNotExist) {
		return r, err
	}
	if r.Profile != NetworkNone {
		links, e := n.links(ctx, "")
		if e != nil {
			return r, e
		}
		for _, link := range links {
			if link.IfName == r.HostInterface || link.IfName == r.PeerInterface {
				return r, errors.New("veth name collides with an existing interface")
			}
		}
	}
	// Both durable ledgers precede dispatch. Any uncertain helper completion leaves
	// the exact name and prefixes retained; Prepare never resubmits that create.
	if err = n.store.ReserveNetwork(ctx, a.Owner, a.Record); err != nil {
		return r, err
	}
	n.owned[a.Owner.InstanceID] = a
	if l.Topology != NetworkNone {
		if err = networkSave(a); err != nil {
			return r, err
		}
	}
	if err = n.store.SubmitCreate(ctx, a.Owner, CreateNetwork, r.NetnsPath); err != nil {
		return r, err
	}
	if err = n.createNativeNamespace(ctx, a); err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), n.cfg.OperationTimeout)
		defer cancel()
		saved := n.save(cleanup, a)
		var uncertain *nativeNamespaceUncertain
		if saved == nil && !errors.As(err, &uncertain) {
			if a.namespacePublished {
				err = errors.Join(err, n.store.ObserveCreated(cleanup, a.Owner, CreateNetwork, r.NetnsPath, fmt.Sprintf("%d:%d", a.Record.NetnsDev, a.Record.NetnsIno)))
			} else {
				err = errors.Join(err, n.store.RejectCreate(cleanup, a.Owner, CreateNetwork, r.NetnsPath, "completed-native-namespace-failure-before-bind"))
			}
		}
		return a.Record, errors.Join(err, saved)
	}
	if err = n.save(ctx, a); err != nil {
		return a.Record, err
	}
	if err = n.store.ObserveCreated(ctx, a.Owner, CreateNetwork, r.NetnsPath, fmt.Sprintf("%d:%d", a.Record.NetnsDev, a.Record.NetnsIno)); err != nil {
		return a.Record, err
	}
	if err = n.configure(ctx, a); err != nil {
		_ = n.emergencyClose(ctx, a)
		return a.Record, err
	}
	topology, err := n.topology(ctx, a)
	if err != nil {
		return a.Record, err
	}
	a.Topology = topology
	if r.Profile != NetworkNone {
		if err = n.captureRules(ctx, a); err != nil {
			return a.Record, err
		}
	}
	a.Record.State = "CLOSED"
	if r.Profile != NetworkNone {
		a.HostInventoryDigest, err = n.inventoryDigest(ctx)
		if err != nil {
			return a.Record, err
		}
	}
	err = n.save(ctx, a)
	return a.Record, err
}
func networkOpenNamespace(a *networkAllocation) (*os.File, error) {
	open := func(path string) (*os.File, unix.Stat_t, error) {
		var st unix.Stat_t
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, st, err
		}
		f := os.NewFile(uintptr(fd), path)
		if err = unix.Fstat(fd, &st); err != nil {
			f.Close()
			return nil, st, err
		}
		var fs unix.Statfs_t
		if err = unix.Fstatfs(fd, &fs); err != nil {
			f.Close()
			return nil, st, err
		}
		kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
		if err != nil || fs.Type != unix.NSFS_MAGIC || kind != unix.CLONE_NEWNET || st.Uid != 0 || st.Gid != 0 {
			f.Close()
			return nil, st, errors.Join(errors.New("owned path is not a root-owned network namespace mount"), err)
		}
		return f, st, nil
	}
	local, st, err := open(a.Record.NetnsPath)
	if err != nil {
		return nil, err
	}
	// PID1 opens NetworkNamespacePath for the future stage. Prove publication in
	// its mount tree after the creation helper has exited, not only in the
	// manager's possibly private view. The named bind and this CLOEXEC FD pin the
	// same kernel namespace independently of the creating helper's lifetime.
	published, pid1, err := open(filepath.Join("/proc/1/root", strings.TrimPrefix(a.Record.NetnsPath, "/")))
	if err != nil {
		local.Close()
		return nil, err
	}
	closeErr := published.Close()
	if closeErr != nil || st.Dev != pid1.Dev || st.Ino != pid1.Ino {
		local.Close()
		return nil, errors.Join(errors.New("network namespace was not published in PID1 mount namespace"), closeErr)
	}
	if a.Record.NetnsIno != 0 && (a.Record.NetnsIno != st.Ino || a.Record.NetnsDev != uint64(st.Dev)) {
		local.Close()
		return nil, errors.New("owned network namespace identity changed")
	}
	a.Record.NetnsDev = uint64(st.Dev)
	a.Record.NetnsIno = st.Ino
	return local, nil
}
func networkObserveNamespace(a *networkAllocation) error {
	pin, err := networkOpenNamespace(a)
	if err != nil {
		return err
	}
	return pin.Close()
}
func (n *Network) configure(ctx context.Context, a *networkAllocation) error {
	r := &a.Record
	ns := r.NetnsPath
	if _, err := n.ip(ctx, ns, "link", "set", "lo", "up"); err != nil {
		return err
	}
	if r.Profile == NetworkNone {
		return nil
	}
	if _, err := n.ip(ctx, "", "link", "add", r.HostInterface, "address", r.HostMAC, "type", "veth", "peer", "name", r.PeerInterface, "address", r.PeerMAC); err != nil {
		return err
	}
	// Persist kernel identities before moving the peer or deleting anything.
	links, err := n.links(ctx, "")
	if err != nil {
		return err
	}
	for _, link := range links {
		if link.IfName == r.HostInterface {
			r.HostIfIndex = link.IfIndex
		}
		if link.IfName == r.PeerInterface {
			r.PeerIfIndex = link.IfIndex
		}
	}
	if r.HostIfIndex == 0 || r.PeerIfIndex == 0 {
		return errors.New("created veth identities not observed")
	}
	if err = n.save(ctx, a); err != nil {
		return err
	}
	if err = n.movePeerNamespace(ctx, a); err != nil {
		return err
	}
	for _, end := range []struct{ ns, name string }{{"", r.HostInterface}, {ns, r.PeerInterface}} {
		if _, err = n.ip(ctx, end.ns, "link", "set", "dev", end.name, "addrgenmode", "none"); err != nil {
			return err
		}
	}
	if err = n.createFirewall(ctx, a); err != nil {
		return err
	}
	for _, v := range []struct{ family, host, peer, prefix string }{{"-4", r.HostIPv4, r.PeerIPv4, "30"}, {"-6", r.HostIPv6, r.PeerIPv6, "126"}} {
		if v.host == "" {
			continue
		}
		for _, end := range []struct{ ns, name, ip, neighbor, mac string }{{"", r.HostInterface, v.host, v.peer, r.PeerMAC}, {ns, r.PeerInterface, v.peer, v.host, r.HostMAC}} {
			args := []string{v.family, "addr", "add", end.ip + "/" + v.prefix, "dev", end.name}
			if v.family == "-6" {
				args = append(args, "nodad")
			}
			if _, err = n.ip(ctx, end.ns, args...); err != nil {
				return err
			}
			if _, err = n.ip(ctx, end.ns, v.family, "neigh", "add", end.neighbor, "lladdr", end.mac, "nud", "permanent", "dev", end.name); err != nil {
				return err
			}
		}
		if _, err = n.ip(ctx, ns, v.family, "route", "add", "default", "via", v.host, "dev", r.PeerInterface); err != nil {
			return err
		}
	}
	if r.Profile == NetworkPublicV4 {
		// No IPv6 address/default next hop is assigned on either end. The peer also
		// has unconditional IPv6 INPUT/OUTPUT/FORWARD deny, not just a host hook.
		for _, chain := range []string{"INPUT", "OUTPUT", "FORWARD"} {
			if _, err = n.tables(ctx, 6, ns, "filter", "-I", chain, "1", "-j", "DROP"); err != nil {
				return err
			}
		}
	}
	if _, err = n.ip(ctx, ns, "link", "set", r.PeerInterface, "up"); err != nil {
		return err
	}
	// Host veth remains DOWN until an authenticated fixed-topology PUBLIC grant.
	return nil
}
func (n *Network) VerifyClosed(ctx context.Context, o Ownership) error {
	if n.reconciliationOnly {
		return invalid("reconciliation-only network cannot authorize stage admission")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	a, err := n.allocation(o)
	if err != nil {
		return err
	}
	if a.Record.State != "CLOSED" {
		return errors.New("network is not durably closed")
	}
	return n.verify(ctx, a, false)
}
func (n *Network) SetEgress(ctx context.Context, o Ownership, policy EgressPolicy) error {
	if n.reconciliationOnly && policy != EgressNone {
		return invalid("reconciliation-only network cannot grant egress")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	a, err := n.allocation(o)
	if err != nil {
		if policy != EgressNone {
			return err
		}
		record, e := n.store.Network(ctx, o)
		if e != nil {
			return n.requireNoNetworkIntent(ctx, o)
		}
		if record.State == "CLEANED" {
			return nil
		}
		if record.Profile != NetworkNone {
			return err
		}
		a = &networkAllocation{Owner: o, BootID: record.BootID, Record: record, Rules: map[string]string{}, Topology: map[string]string{}, Flows: map[string]string{}}
		n.owned[o.InstanceID] = a
	}
	if a.Record.Profile != NetworkNone {
		lock, e := networkLock(ctx)
		if e != nil {
			return e
		}
		defer networkUnlock(lock)
	}
	if o.Unit.Name != "" {
		a.Owner.Unit = o.Unit
	}
	if policy != EgressNone && policy != EgressPublicInternet {
		return invalid("unknown egress policy")
	}
	if policy == EgressNone {
		return n.close(ctx, a)
	}
	if a.Record.Profile == NetworkNone {
		return invalid("NONE topology cannot gain PUBLIC authority")
	}
	if !n.monitorReady || n.monitorErr != nil {
		return errors.New("live network monitor unavailable")
	}
	if a.Record.State != "OPEN" && a.Record.State != "CLOSED" {
		return errors.New("network generation requires reconciliation")
	}
	if err = n.verify(ctx, a, a.Record.State == "OPEN"); err != nil {
		return errors.Join(err, n.close(ctx, a))
	}
	if err = n.close(ctx, a); err != nil {
		return err
	}
	if err = n.preflight(ctx, a); err != nil {
		return err
	}
	blocked, err := n.blocked(ctx)
	if err != nil {
		return err
	}
	a.Record.FilterGeneration = rand.Text()
	a.Record.State = "OPENING"
	if err = n.save(ctx, a); err != nil {
		return err
	}
	for _, family := range []int{4, 6} {
		if err = n.replaceForward(ctx, a, family, blocked, true); err != nil {
			return errors.Join(err, n.emergencyClose(ctx, a))
		}
	}
	if err = n.captureRules(ctx, a); err != nil {
		return errors.Join(err, n.emergencyClose(ctx, a))
	}
	if err = n.verifyRules(ctx, a); err != nil {
		return errors.Join(err, n.emergencyClose(ctx, a))
	}
	// Drain notifications generated while the link was closed, then bind all
	// route/address/rule observations before changing the final physical barrier.
	if err = n.drainNotifications(); err != nil {
		return errors.Join(err, n.emergencyClose(ctx, a))
	}
	a.HostInventoryDigest, err = n.inventoryDigest(ctx)
	if err != nil {
		return err
	}
	if _, err = n.ip(ctx, "", "link", "set", a.Record.HostInterface, "up"); err != nil {
		return errors.Join(err, n.emergencyClose(ctx, a))
	}
	a.Topology, err = n.topology(ctx, a)
	if err != nil {
		return errors.Join(err, n.emergencyClose(ctx, a))
	}
	after, checkErr := n.inventoryDigest(ctx)
	if checkErr != nil || after != a.HostInventoryDigest {
		return errors.Join(errors.New("inventory changed while opening barrier"), checkErr, n.emergencyClose(ctx, a))
	}
	if err = n.drainNotifications(); err != nil {
		return errors.Join(err, n.emergencyClose(ctx, a))
	}
	a.Record.State = "OPEN"
	if err = n.save(ctx, a); err != nil {
		return errors.Join(err, n.emergencyClose(ctx, a))
	}
	return nil
}
func (n *Network) emergencyClose(ctx context.Context, a *networkAllocation) error {
	ctx, cancel := context.WithTimeout(context.Background(), n.cfg.OperationTimeout)
	defer cancel()
	var errs []error
	if a.Record.HostInterface != "" {
		if err := n.verifyLink(ctx, a); err != nil {
			errs = append(errs, err)
		} else {
			_, err = n.ip(ctx, "", "link", "set", a.Record.HostInterface, "down")
			errs = append(errs, err)
		}
	}
	if a.Owner.Unit.Name != "" {
		errs = append(errs, n.systemd.Stop(ctx, a.Owner.Unit))
	}
	a.Record.State = "RECOVERY_REQUIRED"
	errs = append(errs, n.save(ctx, a))
	return errors.Join(errs...)
}
func (n *Network) close(ctx context.Context, a *networkAllocation) error {
	if a.Record.State == "CLEANED" {
		return nil
	}
	if a.Record.Profile == NetworkNone {
		a.Record.State = "CLOSED"
		return n.save(ctx, a)
	}
	var errs []error
	if err := n.verifyLink(ctx, a); err != nil {
		return errors.Join(err, n.emergencyClose(ctx, a))
	}
	// Physical barrier precedes both-family rule replacement and flow deletion.
	_, err := n.ip(ctx, "", "link", "set", a.Record.HostInterface, "down")
	errs = append(errs, err)
	a.Record.State = "CLOSING"
	a.Record.FilterGeneration = rand.Text()
	errs = append(errs, n.save(ctx, a))
	for _, family := range []int{4, 6} {
		errs = append(errs, n.replaceForward(ctx, a, family, nil, false))
	}
	errs = append(errs, n.clearFlows(ctx, a))
	if err = errors.Join(errs...); err != nil {
		return errors.Join(err, n.emergencyClose(ctx, a))
	}
	if err = n.captureRules(ctx, a); err != nil {
		return errors.Join(err, n.emergencyClose(ctx, a))
	}
	a.Topology, err = n.topology(ctx, a)
	if err != nil {
		return errors.Join(err, n.emergencyClose(ctx, a))
	}
	a.HostInventoryDigest, err = n.inventoryDigest(ctx)
	if err != nil {
		return err
	}
	a.Record.State = "CLOSED"
	return n.save(ctx, a)
}
func (n *Network) closeAll(ctx context.Context) error {
	var errs []error
	for _, a := range n.owned {
		if a.Record.State == "OPEN" || a.Record.State == "OPENING" {
			errs = append(errs, n.close(ctx, a))
		}
	}
	return errors.Join(errs...)
}

// Snapshot hashes bind observed kernel facts; they are not proof by object name.
func networkDigest(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
func networkEqualSnapshots(a, b map[string]string) bool {
	return len(a) == len(b) && func() bool {
		for k, v := range a {
			if b[k] != v {
				return false
			}
		}
		return true
	}()
}
func networkJSON(raw []byte, v any) error {
	if len(raw) > 1<<20 {
		return errors.New("network inventory exceeds bound")
	}
	return json.Unmarshal(raw, v)
}
func networkSortedPrefixes(in []netip.Prefix) []netip.Prefix {
	slices.SortFunc(in, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	return slices.Compact(in)
}
func (n *Network) requireNoNetworkIntent(ctx context.Context, o Ownership) error {
	_, err := n.store.Network(ctx, o)
	if err == nil {
		return errors.New("durable network allocation requires reconciliation")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, submitted, err := n.store.LookupCreate(ctx, o, CreateNetwork)
	if err != nil {
		return err
	}
	if submitted {
		return ErrCreateUnresolved
	}
	return nil
}
func networkObservationDigest(a *networkAllocation) (string, error) {
	raw, err := json.Marshal(struct {
		BootID, Generation, Host string
		Rules, Topology, Flows   map[string]string
	}{a.BootID, a.Record.Generation, a.HostInventoryDigest, a.Rules, a.Topology, a.Flows})
	if err != nil {
		return "", err
	}
	return networkDigest(raw), nil
}
func (n *Network) Ready() <-chan struct{} { return n.ready }
