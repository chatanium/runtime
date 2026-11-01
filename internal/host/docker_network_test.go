package host

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"
	"golang.org/x/sys/unix"
)

func networkCommandFixture(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "firewall")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestChainExistsRequiresSuccessfulTableInventory(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		exit         int
		want         bool
	}{
		{"absent", "-P PREROUTING ACCEPT\n-N FMother", 0, false},
		{"present", "-P PREROUTING ACCEPT\n-N FMowned\n-A FMowned -j DROP", 0, true},
		{"not-prefix", "-N FMowned-other\n-A PREROUTING -j FMowned-other", 0, false},
		{"incompatible", "iptables: Incompatible with this kernel.", 1, false},
		{"permission", "Permission denied (you must be root)", 4, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Named-chain lookups deliberately reproduce the host's ambiguous
			// failure. Only a successful complete inventory can prove absence.
			script := "if [ \"$#\" -ne 4 ] || [ \"$4\" != '-S' ]; then\n  echo 'iptables: Incompatible with this kernel.' >&2\n  exit 1\nfi\n"
			script += fmt.Sprintf("printf '%%s\\n' '%s'\nexit %d\n", tc.output, tc.exit)
			bin := networkCommandFixture(t, script)
			got, err := (&networkPolicy{}).chainExists(context.Background(), bin, "raw", "FMowned")
			if got != tc.want {
				t.Fatalf("chain existence = %t, want %t", got, tc.want)
			}
			if tc.exit == 0 {
				if err != nil {
					t.Fatalf("successful inventory rejected: %v", err)
				}
			} else {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != tc.exit {
					t.Fatalf("inventory failure suppressed: %v", err)
				}
			}
		})
	}
}

type networkTestTransport func(*http.Request) (*http.Response, error)

func (f networkTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestObservedNetworkOnlyCleanupUsesAffirmativeFirewallInventory(t *testing.T) {
	for _, inventoryFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("inventory-fails-%t", inventoryFails), func(t *testing.T) {
			ctx := context.Background()
			f := newCreateStateFixture(t, EgressPublicInternet)
			o := f.lease.Ownership
			const objectID = "observed-network"
			identity := containerName(o) + "-net"
			if err := f.journal.SubmitCreate(ctx, o, CreateNetwork, identity); err != nil {
				t.Fatal(err)
			}
			if err := f.journal.ObserveCreated(ctx, o, CreateNetwork, identity, objectID); err != nil {
				t.Fatal(err)
			}
			inventory := "printf '%s\\n' '-P PREROUTING ACCEPT'\nexit 0\n"
			if inventoryFails {
				inventory = "echo 'iptables: Incompatible with this kernel.' >&2\nexit 1\n"
			}
			bin := networkCommandFixture(t, "if [ \"$#\" -eq 4 ] && [ \"$4\" = '-S' ]; then\n"+inventory+"fi\nif [ \"$1\" = '-D' ]; then\n  echo '0 flow entries have been deleted.' >&2\n  exit 1\nfi\necho 'iptables: Incompatible with this kernel.' >&2\nexit 1\n")
			deleted := false
			cli, err := client.New(client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{Transport: networkTestTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/v1.56/networks/"+objectID {
					return nil, fmt.Errorf("unexpected Docker request: %s %s", r.Method, r.URL.Path)
				}
				status := http.StatusOK
				var body any = map[string]any{"Id": objectID, "Name": identity, "Labels": ownershipLabels(o), "Containers": map[string]any{}}
				switch r.Method {
				case http.MethodGet:
					if deleted {
						status = http.StatusNotFound
						body = map[string]string{"message": "network not found"}
					}
				case http.MethodDelete:
					deleted = true
					status = http.StatusNoContent
					body = nil
				default:
					return nil, fmt.Errorf("unexpected Docker method: %s", r.Method)
				}
				data, err := json.Marshal(body)
				if err != nil {
					return nil, err
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(data))), Request: r}, nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cli.Close() })
			policy := &networkPolicy{docker: cli, creates: f.journal, owned: make(map[string]*ownedNetwork), cfg: NetworkConfig{IPv4Pool: "10.240.0.0/16", IPv6Pool: "fd42:8a6b:98c1::/64", IPTables: bin, IP6Tables: bin, IPTablesRestore: bin, IP6TablesRestore: bin, Conntrack: bin}}
			platform := &DockerPlatform{docker: cli, creates: f.journal, network: policy, cfg: DockerConfig{TerminationDeadline: 5 * time.Second}}
			err = platform.Reconcile(ctx, o)
			if !deleted {
				t.Fatal("observed owned network was not removed")
			}
			if inventoryFails {
				if err == nil {
					t.Fatal("network deletion concealed failed firewall cleanup")
				}
				if err := f.journal.cleanup(ctx, o.InstanceID, false, err); err != nil {
					t.Fatal(err)
				}
			} else {
				if err != nil {
					t.Fatalf("observed network-only cleanup failed: %v", err)
				}
				if err := f.journal.cleanup(ctx, o.InstanceID, true, nil); err != nil {
					t.Fatal(err)
				}
			}
			var cleanup string
			if err := f.journal.db.QueryRowContext(ctx, "SELECT cleanup FROM instances WHERE id=?", o.InstanceID).Scan(&cleanup); err != nil {
				t.Fatal(err)
			}
			if (cleanup == "COMPLETE") == inventoryFails {
				t.Fatalf("cleanup status lost firewall proof requirement: %s", cleanup)
			}
			if _, found, err := f.journal.LookupCreate(ctx, o, CreateContainer); err != nil || found {
				t.Fatalf("network-only cleanup fabricated container submission: %t %v", found, err)
			}
		})
	}
}

func TestBridgeIPv6IdentityRequiresGatewayNotLinkLocal(t *testing.T) {
	gateway := netip.MustParseAddr("fd42:8a6b:98c1:0:ffff:ffff:ffff:ff01")
	for _, tc := range []struct {
		name      string
		addresses []string
		linkLocal string
		wantError bool
	}{
		{"empty-docker-bridge", []string{"10.240.255.253/30", gateway.String() + "/120"}, "", false},
		{"joined-endpoint", []string{"fe80::abcd/64", gateway.String() + "/120"}, "fe80::abcd", false},
		{"gateway-only-clears-old-link-local", []string{gateway.String() + "/120"}, "", false},
		{"link-local-only", []string{"fe80::abcd/64"}, "", true},
		{"wrong-gateway", []string{"fd42:8a6b:98c1:0:ffff:ffff:ffff:ff02/120", "fe80::abcd/64"}, "", true},
		{"no-addresses", nil, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var addresses []net.Addr
			for _, raw := range tc.addresses {
				ip, prefix, err := net.ParseCIDR(raw)
				if err != nil {
					t.Fatal(err)
				}
				prefix.IP = ip
				addresses = append(addresses, prefix)
			}
			n := &ownedNetwork{gateway6: gateway, hostLinkLocal6: netip.MustParseAddr("fe80::dead")}
			err := n.setBridgeIPv6Identity(addresses)
			if (err != nil) != tc.wantError {
				t.Fatalf("bridge identity error = %v, want error %t", err, tc.wantError)
			}
			if !tc.wantError {
				want := netip.Addr{}
				if tc.linkLocal != "" {
					want = netip.MustParseAddr(tc.linkLocal)
				}
				if n.hostLinkLocal6 != want {
					t.Fatalf("bridge link-local = %s, want %s", n.hostLinkLocal6, want)
				}
			}
		})
	}
}

func TestNetworkRulesWithoutBridgeLinkLocalPreserveDualStackDenials(t *testing.T) {
	scriptPath := filepath.Join(t.TempDir(), "rules")
	bin := networkCommandFixture(t, "if [ \"$1\" = '--wait' ]; then\n  cat > '"+scriptPath+"'\nelse\n  printf '%s\\n' '-N FMowned'\nfi\n")
	p := &networkPolicy{cfg: NetworkConfig{IPTables: bin, IP6Tables: bin, IPTablesRestore: bin, IP6TablesRestore: bin, Resolvers: []string{"1.1.1.1", "2606:4700:4700::1111"}}}
	n := &ownedNetwork{chain: "FMowned", bridge: "fmlabempty0", ipv4: netip.MustParseAddr("10.240.255.254"), ipv6: netip.MustParseAddr("fd42:8a6b:98c1:0:ffff:ffff:ffff:ff02"), gateway6: netip.MustParseAddr("fd42:8a6b:98c1:0:ffff:ffff:ffff:ff01"), linkLocal6: netip.MustParseAddr("fe80::2"), fingerprints: make(map[string][32]byte)}
	for family := range 2 {
		if err := p.installRules(context.Background(), n, family, specialPurposePrefixes, true); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(scriptPath)
		if err != nil {
			t.Fatal(err)
		}
		script := string(raw)
		if strings.Contains(script, "invalid IP") {
			t.Fatal("optional bridge link-local generated an invalid rule")
		}
		required := []string{
			"-m addrtype --dst-type LOCAL -j DROP",
			"-i fmlabempty0 -o fmlabempty0 -j DROP",
			"-p udp --dport 53 -j DROP",
			"-p tcp --dport 53 -j DROP",
			"-p 4 -j DROP", "-p 41 -j DROP", "-p 47 -j DROP",
			"-p udp --dport 3544 -j DROP",
			"-o fmlabempty0 -j DROP",
		}
		for _, prefix := range specialPurposePrefixes {
			if prefix.Addr().Is6() == (family == 1) {
				required = append(required, "-d "+prefix.String()+" -j DROP", "-o fmlabempty0 -s "+prefix.String()+" -j DROP")
			}
		}
		if family == 1 {
			required = append(required,
				"! -d 2000::/3 -j DROP",
				"-i fmlabempty0 -s "+n.ipv6.String()+" -d "+n.gateway6.String()+" -p ipv6-icmp --icmpv6-type 136 -m hl --hl-eq 255 -j ACCEPT",
				"-i fmlabempty0 -s fe80::2 -d ff02::1:ffff:ff01 -p ipv6-icmp --icmpv6-type 135 -m hl --hl-eq 255 -j ACCEPT",
				"-p udp -d 2606:4700:4700::1111 --dport 53 -j RETURN",
			)
		} else {
			required = append(required, "-p udp -d 1.1.1.1 --dport 53 -j RETURN")
		}
		for _, rule := range required {
			if !strings.Contains(script, rule) {
				t.Errorf("family %d missing required rule %q", family, rule)
			}
		}
	}
}

func routeMessage(kind uint16) []byte {
	message := make([]byte, unix.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(message[:4], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:6], kind)
	return message
}

func routeSocketFixture(t *testing.T) (*os.File, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	receiver := os.NewFile(uintptr(fds[0]), "route-receiver")
	sender := os.NewFile(uintptr(fds[1]), "route-sender")
	t.Cleanup(func() {
		receiver.Close()
		sender.Close()
	})
	if err := unix.SetsockoptInt(fds[1], unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<20); err != nil {
		t.Fatal(err)
	}
	return receiver, fds[1]
}

func sendRouteMessage(t *testing.T, sender int, message []byte) {
	t.Helper()
	if n, err := unix.SendmsgN(sender, message, nil, nil, unix.MSG_DONTWAIT); err != nil || n != len(message) {
		t.Fatalf("queue route notification: %d %v", n, err)
	}
}

func TestRouteNotificationFramingFailsClosed(t *testing.T) {
	valid := routeMessage(unix.RTM_NEWADDR)
	badLength := routeMessage(unix.RTM_NEWADDR)
	binary.NativeEndian.PutUint32(badLength[:4], uint32(len(badLength)+1))
	for _, tc := range []struct {
		name    string
		message []byte
		flags   int
		wantErr bool
	}{
		{"valid", valid, 0, false},
		{"multiple", append(append([]byte{}, valid...), valid...), 0, false},
		{"empty", nil, 0, true},
		{"short-header", valid[:8], 0, true},
		{"bad-length", badLength, 0, true},
		{"overrun", routeMessage(unix.NLMSG_OVERRUN), 0, true},
		{"kernel-error", routeMessage(unix.NLMSG_ERROR), 0, true},
		{"datagram-truncated", valid, unix.MSG_TRUNC, true},
		{"control-truncated", valid, unix.MSG_CTRUNC, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := routeNotificationError(tc.message, tc.flags); (err != nil) != tc.wantErr {
				t.Fatalf("notification validation = %v, want error %t", err, tc.wantErr)
			}
		})
	}
}

func TestRouteNotificationReadDetectsSocketTruncation(t *testing.T) {
	receiver, sender := routeSocketFixture(t)
	sendRouteMessage(t, sender, routeMessage(unix.RTM_NEWADDR))
	if err := readRouteNotification(receiver, make([]byte, 8)); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("truncated initial datagram accepted: %v", err)
	}
}

func TestRouteNotificationDrainIsBounded(t *testing.T) {
	receiver, sender := routeSocketFixture(t)
	for range 256 {
		sendRouteMessage(t, sender, routeMessage(unix.RTM_NEWROUTE))
	}
	if err := drainRouteNotifications(receiver, make([]byte, 65536)); err == nil || !strings.Contains(err.Error(), "count bound") {
		t.Fatalf("notification flood did not fail closed at its bound: %v", err)
	}
}

func routePolicyFixture(t *testing.T) (*networkPolicy, string) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "closed")
	bin := networkCommandFixture(t, "if [ \"$1\" = '--wait' ]; then\n  cat > /dev/null\n  echo closed >> '"+logPath+"'\n  exit 0\nfi\nif [ \"$1\" = '-D' ]; then\n  echo '0 flow entries have been deleted.' >&2\n  exit 1\nfi\nprintf '%s\\n' '-N FMowned'\n")
	n := &ownedNetwork{
		owner: Ownership{InstallationID: "installation", EpochID: "epoch", InstanceID: "instance", ContainerID: "container"},
		chain: "FMowned", bridge: "not-a-host-interface",
		ipv4: netip.MustParseAddr("10.240.0.2"), ipv6: netip.MustParseAddr("fd42:8a6b:98c1::2"),
		policyInstalled: true, fingerprints: make(map[string][32]byte),
	}
	return &networkPolicy{
		timeout: 5 * time.Second, owned: map[string]*ownedNetwork{n.owner.InstanceID: n},
		cfg: NetworkConfig{IPTables: bin, IP6Tables: bin, IPTablesRestore: bin, IP6TablesRestore: bin, Conntrack: bin},
	}, logPath
}

func TestRouteBurstCoalescesQueuedNotificationsAndClosesInactivePolicy(t *testing.T) {
	receiver, sender := routeSocketFixture(t)
	p, logPath := routePolicyFixture(t)
	buffer := make([]byte, 65536)
	for range 3 {
		sendRouteMessage(t, sender, routeMessage(unix.RTM_NEWADDR))
	}
	if err := readRouteNotification(receiver, buffer); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	kill := p.reconcileRouteBurstLocked(receiver, buffer, nil)
	p.mu.Unlock()
	if len(kill) != 0 || p.watchErr != nil {
		t.Fatalf("ordinary burst failed: %v %v", kill, p.watchErr)
	}
	log, err := os.ReadFile(logPath)
	if err != nil || len(strings.Fields(string(log))) != 2 {
		t.Fatalf("queued notifications did not close once per family: %q %v", log, err)
	}
	raw, err := receiver.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var receiveErr error
	if err := raw.Control(func(fd uintptr) {
		_, _, _, _, receiveErr = unix.Recvmsg(int(fd), buffer, nil, unix.MSG_DONTWAIT)
	}); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(receiveErr, unix.EAGAIN) {
		t.Fatalf("startup notifications remained queued for replay: %v", receiveErr)
	}
	// An event arriving after the drained burst must initiate another closure,
	// not be lost because the previous interval already reconciled.
	sendRouteMessage(t, sender, routeMessage(unix.RTM_NEWROUTE))
	if err := readRouteNotification(receiver, buffer); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	kill = p.reconcileRouteBurstLocked(receiver, buffer, nil)
	p.mu.Unlock()
	log, err = os.ReadFile(logPath)
	if len(kill) != 0 || p.watchErr != nil || err != nil || len(strings.Fields(string(log))) != 4 {
		t.Fatalf("later event was not reconciled separately: %v %v %q %v", kill, p.watchErr, log, err)
	}
}

func TestRouteBurstLossKeepsEveryBoundPolicyClosed(t *testing.T) {
	receiver, sender := routeSocketFixture(t)
	p, logPath := routePolicyFixture(t)
	other := *p.owned["instance"]
	other.owner.InstanceID, other.owner.ContainerID = "other-instance", "other-container"
	other.chain, other.enabled = "FMother", true
	other.fingerprints = make(map[string][32]byte)
	p.owned[other.owner.InstanceID] = &other
	sendRouteMessage(t, sender, routeMessage(unix.RTM_NEWADDR))
	sendRouteMessage(t, sender, routeMessage(unix.NLMSG_OVERRUN))
	buffer := make([]byte, 65536)
	if err := readRouteNotification(receiver, buffer); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	kill := p.reconcileRouteBurstLocked(receiver, buffer, nil)
	p.mu.Unlock()
	if p.watchErr == nil || len(kill) != 2 {
		t.Fatalf("notification loss did not revoke every bound sandbox: %v %v", p.watchErr, kill)
	}
	killed := make(map[string]bool)
	for _, owner := range kill {
		killed[owner.InstanceID] = true
	}
	for id, n := range p.owned {
		if n.enabled || !killed[id] {
			t.Fatalf("policy reopened or omitted after monitor loss: %s", id)
		}
	}
	log, err := os.ReadFile(logPath)
	if err != nil || len(strings.Fields(string(log))) != 8 {
		t.Fatalf("both policies were not closed in both families: %q %v", log, err)
	}
}

func TestNetworkEnableRejectsLostRouteMonitor(t *testing.T) {
	p := &networkPolicy{watchErr: errors.New("route monitor reported notification loss")}
	// A nil Docker client detects any attempt to reopen after observation loss.
	err := p.enable(context.Background(), &ownedNetwork{})
	var hostError *Error
	if !errors.As(err, &hostError) || hostError.Reason != "HOST_PREREQUISITE_FAILED" {
		t.Fatalf("egress opening did not preserve route-monitor failure: %v", err)
	}
}

func generationPolicyFixture(t *testing.T) (*networkPolicy, *ownedNetwork, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "restore-scripts")
	bin := networkCommandFixture(t, "if [ \"$1\" = '--wait' ]; then\n  cat >> '"+path+"'\n  exit 0\nfi\nif [ \"$1\" = '-D' ]; then\n  echo '0 flow entries have been deleted.' >&2\n  exit 1\nfi\nprintf '%s\\n' '-N FMowned'\n")
	n := &ownedNetwork{
		owner: Ownership{InstallationID: "installation", EpochID: "epoch", InstanceID: "instance"},
		chain: "FMowned", bridge: "fmfixture",
		ipv4: netip.MustParseAddr("10.240.0.2"), ipv6: netip.MustParseAddr("fd42:8a6b:98c1::2"),
		gateway6: netip.MustParseAddr("fd42:8a6b:98c1::1"), linkLocal6: netip.MustParseAddr("fe80::2"),
		policyInstalled: true, fingerprints: make(map[string][32]byte),
	}
	p := &networkPolicy{
		owned: map[string]*ownedNetwork{n.owner.InstanceID: n},
		cfg: NetworkConfig{IPTables: bin, IP6Tables: bin, IPTablesRestore: bin, IP6TablesRestore: bin,
			Conntrack: bin, Resolvers: []string{"1.1.1.1", "2606:4700:4700::1111"}},
	}
	return p, n, path
}

func TestEveryPolicyReplacementChangesGenerationWithoutChangingActions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		action  string
		chains  int
		replace func(*networkPolicy, *ownedNetwork) error
	}{
		{"allocation", "DROP", 6, func(p *networkPolicy, n *ownedNetwork) error {
			return p.installHooks(context.Background(), n)
		}},
		{"disable", "DROP", 6, func(p *networkPolicy, n *ownedNetwork) error {
			return p.disableLocked(context.Background(), n)
		}},
		{"cleanup-revoke", "DROP", 6, func(p *networkPolicy, n *ownedNetwork) error {
			return p.revokeForCleanup(context.Background(), n.owner)
		}},
		{"cleanup-remove", "DROP", 6, func(p *networkPolicy, n *ownedNetwork) error {
			return p.remove(context.Background(), n)
		}},
		{"enabled-ipv4", "RETURN", 3, func(p *networkPolicy, n *ownedNetwork) error {
			return p.installRules(context.Background(), n, 0, specialPurposePrefixes, true)
		}},
		{"enabled-ipv6", "RETURN", 3, func(p *networkPolicy, n *ownedNetwork) error {
			return p.installRules(context.Background(), n, 1, specialPurposePrefixes, true)
		}},
		{"closed-ipv4", "DROP", 3, func(p *networkPolicy, n *ownedNetwork) error {
			return p.installRules(context.Background(), n, 0, specialPurposePrefixes, false)
		}},
		{"closed-ipv6", "DROP", 3, func(p *networkPolicy, n *ownedNetwork) error {
			return p.installRules(context.Background(), n, 1, specialPurposePrefixes, false)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, n, path := generationPolicyFixture(t)
			if tc.name == "cleanup-remove" {
				f := newCreateStateFixture(t, EgressPublicInternet)
				n.owner = f.lease.Ownership
				n.name = containerName(n.owner) + "-net"
				p.owned = map[string]*ownedNetwork{n.owner.InstanceID: n}
				if err := f.journal.SubmitCreate(context.Background(), n.owner, CreateNetwork, n.name); err != nil {
					t.Fatal(err)
				}
				if err := f.journal.ObserveCreated(context.Background(), n.owner, CreateNetwork, n.name, "observed-network"); err != nil {
					t.Fatal(err)
				}
				p.creates = f.journal
				cli, err := client.New(client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{
					Transport: networkTestTransport(func(r *http.Request) (*http.Response, error) {
						if r.Method != http.MethodGet || r.URL.Path != "/v1.56/networks/observed-network" {
							return nil, fmt.Errorf("unexpected Docker request: %s %s", r.Method, r.URL.Path)
						}
						return &http.Response{StatusCode: http.StatusNotFound,
							Header: http.Header{"Content-Type": {"application/json"}},
							Body:   io.NopCloser(strings.NewReader(`{"message":"network not found"}`)), Request: r}, nil
					}),
				}))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { cli.Close() })
				p.docker = cli
			}
			var previous, previousNormalized, previousGeneration string
			offset := 0
			for range 2 {
				if err := tc.replace(p, n); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				script := string(data[offset:])
				offset = len(data)
				generation := ""
				markers := 0
				for line := range strings.SplitSeq(script, "\n") {
					fields := strings.Fields(line)
					for i, field := range fields {
						if field != "--comment" {
							continue
						}
						if i+1 >= len(fields) || !strings.HasPrefix(fields[i+1], "fm-generation:") {
							t.Fatalf("invalid generation marker: %q", line)
						}
						token := fields[i+1]
						if generation == "" {
							generation = token
						}
						if token != generation || !strings.HasSuffix(line, " -j "+tc.action) {
							t.Fatalf("generation replaced an action or differs within operation: %q", line)
						}
						markers++
					}
				}
				if generation == "" || markers != tc.chains || strings.Count(script, "COMMIT\n") != markers {
					t.Fatalf("not every replaced chain has exactly one marker: %d markers, want %d", markers, tc.chains)
				}
				normalized := strings.ReplaceAll(script, generation, "fm-generation:<install>")
				if previous != "" {
					if generation == previousGeneration || script == previous {
						t.Fatal("identical zero-counter replacement concealed a new installation")
					}
					if normalized != previousNormalized {
						t.Fatal("generation tagging changed policy rules or terminal actions")
					}
				}
				previous, previousNormalized, previousGeneration = script, normalized, generation
			}
		})
	}
}

func TestResolverFileGuestPermissionsIgnoreSupervisorUmask(t *testing.T) {
	const childMask = "FLEXMODULE_RESOLVER_TEST_UMASK"
	if mask := os.Getenv(childMask); mask != "" {
		// Umask is process-global: change it only in this isolated test child,
		// after creating the traversable private parent directory.
		directory := t.TempDir()
		switch mask {
		case "0077":
			unix.Umask(0077)
		case "0777":
			unix.Umask(0777)
		default:
			t.Fatalf("unexpected child umask %q", mask)
		}
		p := &networkPolicy{cfg: NetworkConfig{Resolvers: []string{"1.1.1.1", "1.0.0.1"}}}
		path, err := p.resolverFile(directory)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0444 {
			t.Fatalf("guest resolver permissions depend on supervisor umask: %v", info.Mode())
		}
		contents, err := os.ReadFile(path)
		if err != nil || string(contents) != "nameserver 1.1.1.1\nnameserver 1.0.0.1\n" {
			t.Fatalf("resolver configuration changed or is unreadable: %q %v", contents, err)
		}
		if _, err := p.resolverFile(directory); !errors.Is(err, os.ErrExist) {
			t.Fatalf("existing resolver file was not protected by exclusive creation: %v", err)
		}
		return
	}
	for _, mask := range []string{"0077", "0777"} {
		t.Run(mask, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestResolverFileGuestPermissionsIgnoreSupervisorUmask$")
			cmd.Env = append(os.Environ(), childMask+"="+mask)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("resolver permissions under umask %s: %v\n%s", mask, err, output)
			}
		})
	}
}
