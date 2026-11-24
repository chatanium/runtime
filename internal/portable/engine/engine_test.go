package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestResourceLimitsRejectPinnedEngineClamping(t *testing.T) {
	target := Target{OS: "linux", Arch: "amd64", HostCPUs: 4}
	valid := ResourceLimits{CPUMillicores: 10, MemoryBytes: 6 << 20, MaxPIDs: 4 << 20}
	if err := ValidateResourceLimits(target, valid); err != nil {
		t.Fatal(err)
	}
	for _, r := range []ResourceLimits{
		{9, valid.MemoryBytes, valid.MaxPIDs},
		{4_001, valid.MemoryBytes, valid.MaxPIDs},
		{valid.CPUMillicores, valid.MemoryBytes - 1, valid.MaxPIDs},
		{valid.CPUMillicores, 1<<53 + 1, valid.MaxPIDs},
		{valid.CPUMillicores, valid.MemoryBytes, 0},
		{valid.CPUMillicores, valid.MemoryBytes, valid.MaxPIDs + 1},
	} {
		if err := ValidateResourceLimits(target, r); err == nil {
			t.Errorf("accepted unrepresentable pinned GVX resources: %+v", r)
		}
	}
}

func TestRunPlanStartsDenyFirstWithOneScratch(t *testing.T) {
	target := Target{OS: "linux", Arch: "amd64", HostCPUs: 4}
	grant := ApprovedGrant{
		Identity: InstanceIdentity{"installation", "epoch", "instance", "review"},
		Limits:   ResourceLimits{500, 128 << 20, 64},
		Network:  NetworkGrant{Mode: NetworkPublicInternet, Family: IPv4, DNS: []netip.Addr{netip.MustParseAddr("9.9.9.9")}, TXBPS: 1_000, RXBPS: 2_000},
		Launch: LaunchSpec{
			CacheDir: "/owned/cache", ImageRef: executionRefPrefix + strings.Repeat("a", 64),
			HelperPath: "/owned/guest-bridge", DenyPolicyPath: "/owned/deny.json",
			Endpoint: Endpoint{SocketPath: "/owned/instance/control"},
		},
	}
	volumes := VolumeLease{"/owned/data.ext4", 64 << 20, 32 << 20}
	plan, err := PlanRun(target, grant, volumes)
	if err != nil {
		t.Fatal(err)
	}
	args := plan.Args()
	for _, flag := range []string{
		"--backend=systrap", "--platform=linux/amd64", "--lockdown=true", "--privileged=false", "--pull=never",
		"--read-only=true", "--cpus=0.500", "--memory=134217728", "--pids-limit=64",
		"--net=nat", "--isolate-lan=true", "--nat-policy-file=/owned/deny.json", "--host-dns=9.9.9.9",
		"--net-tx-bps=1000", "--net-rx-bps=2000", "-P=false", "--auto-publish=false", "--dynamic-ports=false",
		"--mount=type=volume,src=/owned/data.ext4,dst=" + DataMountpoint + ",driver=ext4lite,size=64m",
		"--mount=type=volume,dst=" + ScratchMountpoint + ",driver=ext4lite,size=32m,ephemeral",
		"--mount=type=bind,src=/owned/guest-bridge,dst=" + BridgeMountpoint + ",readonly",
	} {
		if !slices.Contains(args, flag) {
			t.Errorf("missing argv element %q", flag)
		}
	}
	if strings.Count(strings.Join(args, "\n"), ",ephemeral") != 1 || !slices.Equal(args[len(args)-2:], []string{"--", "--stdio-portable-v2"}) {
		t.Fatalf("bad scratch or trusted entrypoint argv: %q", args)
	}
	if !bytes.Equal(plan.DenyPolicyJSON(), []byte(`{"egress":{"default":"deny"},"ingress":{"default":"deny"}}`)) {
		t.Fatalf("startup policy is not deny-both: %s", plan.DenyPolicyJSON())
	}
	if digest, err := NetworkPolicyDigest(grant.Network); err != nil || digest == "" || digest != plan.EgressPolicyDigest() {
		t.Fatalf("approval digest differs from run policy: %s / %s: %v", digest, plan.EgressPolicyDigest(), err)
	}
	grant.Launch.DenyPolicyPath = ""
	grant.Network = NetworkGrant{Mode: NetworkNone}
	plan, err = PlanRun(target, grant, volumes)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(plan.Args(), "--net=none") || plan.DenyPolicyJSON() != nil || plan.EgressPolicyDigest() != "" ||
		strings.Contains(strings.Join(plan.Args(), "\n"), "--net-tx-bps=") {
		t.Fatalf("NONE carried a NAT setting: %q", plan.Args())
	}
}

func TestApprovedPolicyRuleOrderAndStrictReadback(t *testing.T) {
	g := NetworkGrant{
		Mode: NetworkPublicInternet, Family: IPv4,
		DNS:              []netip.Addr{netip.MustParseAddr("::ffff:9.9.9.9")},
		Excluded:         []netip.Prefix{netip.MustParsePrefix("::ffff:8.8.8.0/120")},
		AllowUnlimitedTX: true, RXBPS: 64_000,
	}
	n, err := planNetwork(g)
	if err != nil {
		t.Fatal(err)
	}
	var policy natPolicy
	if err := json.Unmarshal(n.policy, &policy); err != nil {
		t.Fatal(err)
	}
	rules := policy.Egress.Rules
	gatewayDNS := policyRule{Action: "allow", CIDR: "10.0.2.3/32", Protocol: "tcp", Ports: "53"}
	blockedHost := policyRule{Action: "deny", CIDR: "8.8.8.0/24"}
	upstreamDNS := policyRule{Action: "allow", CIDR: "9.9.9.9/32", Protocol: "udp", Ports: "53"}
	otherDNS := policyRule{Action: "deny", Protocol: "udp", Ports: "53"}
	teredo := policyRule{Action: "deny", Protocol: "udp", Ports: "3544"}
	publicUDP := policyRule{Action: "allow", CIDR: "0.0.0.0/0", Protocol: "udp"}
	want := []policyRule{gatewayDNS, blockedHost, upstreamDNS, otherDNS, teredo, publicUDP}
	last := -1
	for _, rule := range want {
		i := slices.Index(rules, rule)
		if i <= last {
			t.Fatalf("misordered or missing rule %+v: %s", rule, n.policy)
		}
		last = i
	}
	if policy.Egress.Default != "deny" || policy.Ingress.Default != "deny" || len(policy.Ingress.Rules) > 0 {
		t.Fatalf("not default deny for both directions: %s", n.policy)
	}
	if err := verifyPolicy(n.policy, n.policy); err != nil {
		t.Fatal(err)
	}
	if err := verifyPolicy([]byte(denyPolicyJSON), []byte(denyPolicyJSON)); err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []string{"null", `{"egress":{"default":"allow","default":"deny"},"ingress":{"default":"deny"}}`} {
		if err := verifyPolicy([]byte(malformed), []byte(denyPolicyJSON)); !errors.Is(err, ErrApprovalMismatch) {
			t.Errorf("invalid readback %s not rejected: %v", malformed, err)
		}
	}
	g.AllowUnlimitedTX = false
	if _, err := planNetwork(g); err == nil {
		t.Fatal("implicit unlimited rate accepted")
	}
	g.AllowUnlimitedTX = true
	g.Family = "dual-stack"
	if _, err := planNetwork(g); !errors.Is(err, ErrUnsupportedTarget) {
		t.Fatalf("unproved dual-stack result: %v", err)
	}
}

func TestWindowsPreparationRequiresWHPXAndLocalToken(t *testing.T) {
	target := Target{OS: "windows", Arch: "arm64", HostCPUs: 2}
	spec := PreparationSpec{
		CacheDir: `C:\owned\cache`, HelperPath: `C:\owned\preparer`, CompilerPath: `C:\owned\compiler`,
		ScratchBytes: 32 << 20,
		Identity:     InstanceIdentity{"installation", "epoch", "preparation", "review"},
		Endpoint:     Endpoint{SocketPath: `C:\owned\instance\control`},
	}
	limits := ResourceLimits{250, 128 << 20, 128}
	if _, err := PlanPreparation(target, limits, spec); err == nil {
		t.Fatal("Windows engine control permitted without a protected token")
	}
	spec.Endpoint.TokenPath = `C:\owned\instance\token`
	plan, err := PlanPreparation(target, limits, spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{
		"--backend=whpx", "--platform=linux/arm64", "--allow-unconfined-systrap=false", "--net=none",
		`--control-socket=unix:C:\owned\instance\control`, `--control-token-file=C:\owned\instance\token`,
		`--bin=C:\owned\preparer`, `--mount=type=bind,src=C:\owned\compiler,dst=/chatanium-compiler,readonly`,
	} {
		if !slices.Contains(plan.Args(), flag) {
			t.Errorf("missing argv element %q", flag)
		}
	}
}

func TestStartupCancellationPreservesPeerEvidence(t *testing.T) {
	done := make(chan struct{})
	close(done)
	adapter := GVXAdapter{peer: Peer{Done: done, Exited: func() bool { return true }}}
	caller, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := adapter.startupError(caller, context.Canceled); !errors.Is(err, ErrPeerExited) || errors.Is(err, context.Canceled) {
		t.Fatalf("locally canceled startup must report observed native exit: %v", err)
	}
	cancel()
	if err := adapter.startupError(caller, context.Canceled); !errors.Is(err, ErrPeerExited) || !errors.Is(err, context.Canceled) {
		t.Fatalf("racing caller cancellation and native exit must both be retained: %v", err)
	}
	if err := adapter.startupError(caller, ErrCapabilityMissing); err != ErrCapabilityMissing {
		t.Fatalf("explicit capability failure was hidden by startup races: %v", err)
	}
}
