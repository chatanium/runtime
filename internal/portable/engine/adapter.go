package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/thirdscam/chatanium/internal/portable/process"
)

const (
	connectTimeout = 30 * time.Second
	requestTimeout = 10 * time.Second
	startupPoll    = 20 * time.Millisecond
	maxStopGrace   = time.Minute
)

// Peer identifies the process scope the supervisor already owns. Kill must
// safely request forced termination outside the RPC context and not depend on
// that connection. Done closes after the caller's lifetime observer finishes;
// if that observer can fail, Exited must confirm positive exit proof. No PID
// lookup or adoption is performed. The caller still owns cleanup of artifacts.
type Peer struct {
	Done   <-chan struct{}
	Kill   func() error
	Exited func() bool
	// Completing is optional and must be nonblocking. Only report true after
	// validated bridge EXIT. It allows a brief native drain on EOF, never
	// another control operation.
	Completing func() bool
}

// EgressPolicy carries the caller's authorization decision for a verified
// module and the complete reviewed identity. It cannot supply arbitrary rules;
// open installs only the policy compiled in RunPlan. Revoke is terminal.
type EgressPolicy struct {
	Identity InstanceIdentity
	Open     bool
}

type GVXAdapter struct {
	plan      RunPlan
	peer      Peer
	wire      controlWire
	done      chan struct{}
	gate      chan struct{} // serializes verification and all mutations
	open      bool          // protected by gate
	stopping  atomic.Bool
	stopReply atomic.Bool

	finish  sync.Once
	kill    sync.Once
	mu      sync.Mutex
	err     error
	killErr error
}

var baseCapabilities = [...]string{
	"sandbox.inspect", "mount.list", "lifecycle.stop", "resource.cpu", "resource.memory", "resource.pids",
}
var natCapabilities = [...]string{"net.policy.read", "net.policy.write", "resource.network"}

// Connect waits for the planned local endpoint, authenticates one gvx-ctrl/2
// session, and verifies its deny-first or NONE initial state. A failed Connect
// is terminal: it waits for owned native exit, attempting forced termination
// when needed. ErrExitUnconfirmed means cleanup must keep its reservations.
func Connect(caller context.Context, plan RunPlan, peer Peer) (*GVXAdapter, error) {
	if peer.Done == nil || peer.Kill == nil {
		return nil, errors.New("GVX Connect requires an owned exit observer and kill callback")
	}
	a := &GVXAdapter{plan: plan, peer: peer, done: make(chan struct{}), gate: make(chan struct{}, 1)}
	ctx := caller
	if _, hasDeadline := caller.Deadline(); !hasDeadline {
		var cancelLimit context.CancelFunc
		ctx, cancelLimit = context.WithTimeout(caller, connectTimeout)
		defer cancelLimit()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	fail := func(err error) (*GVXAdapter, error) {
		return nil, a.failConnect(caller, a.startupError(caller, err))
	}
	if plan.sandboxID == "" || plan.target.OS != runtime.GOOS || plan.target.Arch != runtime.GOARCH {
		return fail(fmt.Errorf("%w: invalid plan or plan does not match local target", ErrUnsupportedTarget))
	}
	if err := process.CheckPrivateDir(filepath.Dir(plan.endpoint.SocketPath)); err != nil {
		return fail(fmt.Errorf("untrusted GVX control directory: %w", err))
	}
	go func() {
		select {
		case <-peer.Done:
			cancel()
		case <-ctx.Done():
		}
	}()
	conn, token, err := awaitEndpoint(ctx, plan.endpoint)
	if err != nil {
		return fail(err)
	}
	a.wire.conn = conn
	hello, err := negotiate(ctx, conn, token)
	if err != nil {
		return fail(fmt.Errorf("authenticate GVX control: %w", err))
	}
	if hello.SandboxID != plan.sandboxID {
		return fail(fmt.Errorf("%w: GVX HELLO sandbox ID mismatch", ErrApprovalMismatch))
	}
	if err := a.verifyCapabilities(hello.Capabilities); err != nil {
		return fail(err)
	}
	if plan.network.mode == NetworkPublicInternet {
		netQoS := false
		for _, feature := range hello.Features {
			if feature == "net_qos" {
				netQoS = true
			}
		}
		if !netQoS || hello.MaxFrame <= maxPolicyBytes+64 {
			return fail(fmt.Errorf("%w: GVX NAT QoS or policy framing", ErrCapabilityMissing))
		}
	}
	a.wire.maxFrame, a.wire.next, a.wire.responses = hello.MaxFrame, 1, make(chan frame, 1)
	go a.readControl()
	go func() {
		select {
		case <-peer.Done:
			err := a.exitStatus()
			a.terminate(err, err == ErrExitUnconfirmed)
		case <-a.done:
		}
	}()
	if err := a.verifyStartup(ctx); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if err := a.live(); err != nil {
		return fail(err)
	}
	return a, nil
}

func (a *GVXAdapter) startupError(caller context.Context, err error) error {
	// Only transport and shutdown races are ambiguous. An explicit capability,
	// identity, or policy rejection must not disappear when the peer also exits.
	var rpcErr *RPCError
	if !(errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, ErrControlLost) ||
		errors.Is(err, ErrPeerClosing) || errors.Is(err, ErrPeerExited) ||
		errors.Is(err, ErrExitUnconfirmed) || errors.As(err, &rpcErr) && rpcErr.Code == "SANDBOX_EXITING") {
		return err
	}
	if a.peerEnded() {
		peerErr := a.exitStatus()
		if errors.Is(err, context.Canceled) || errors.Is(err, ErrPeerClosing) || errors.Is(err, peerErr) {
			err = peerErr
		} else {
			err = errors.Join(peerErr, err)
		}
	}
	if callerErr := caller.Err(); callerErr != nil && !errors.Is(err, callerErr) {
		err = errors.Join(callerErr, err)
	}
	return err
}

func (a *GVXAdapter) failConnect(caller context.Context, err error) error {
	if errors.Is(err, ErrPeerClosing) && caller.Err() == nil {
		// Authenticated GOAWAY after Sandbox.Run can race the native observer.
		// Do not turn an already orderly guest exit into a forced signal.
		ctx, cancel := context.WithTimeout(caller, requestTimeout)
		exitErr := a.waitExit(ctx)
		cancel()
		if exitErr == nil {
			a.terminate(ErrPeerExited, false)
			return a.startupError(caller, err)
		}
	}
	a.terminate(err, true)
	// Caller cancellation closes control, but cannot prove cleanup. Give the
	// owned kill/observer a separate bounded window to reap native writers.
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	if exitErr := a.waitExit(ctx); exitErr != nil {
		return errors.Join(err, exitErr)
	}
	return err
}

func awaitEndpoint(ctx context.Context, endpoint Endpoint) (*net.UnixConn, string, error) {
	for {
		var token []byte
		var err error
		if endpoint.TokenPath != "" {
			token, err = process.ReadEngineToken(endpoint.TokenPath)
			if err != nil && !notReady(err) {
				return nil, "", fmt.Errorf("read GVX token: %w", err)
			}
		}
		if err == nil {
			conn, dialErr := process.DialEngine(ctx, endpoint.SocketPath)
			if dialErr == nil {
				local, ok := conn.(*net.UnixConn)
				if !ok {
					_ = conn.Close()
					return nil, "", errors.New("GVX endpoint is not AF_UNIX")
				}
				return local, string(token), nil
			}
			if !notReady(dialErr) && !connectionRefused(dialErr) {
				return nil, "", fmt.Errorf("authenticate GVX endpoint: %w", dialErr)
			}
		}
		if err := waitStartup(ctx); err != nil {
			return nil, "", fmt.Errorf("wait for GVX endpoint: %w", err)
		}
	}
}

func notReady(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, process.ErrEndpointNotReady)
}

func connectionRefused(err error) bool {
	// Winsock returns WSAECONNREFUSED, not the POSIX compatibility errno.
	return errors.Is(err, syscall.ECONNREFUSED) || runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(10061))
}

func waitStartup(ctx context.Context) error {
	t := time.NewTimer(startupPoll)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *GVXAdapter) verifyCapabilities(caps []string) error {
	want := len(baseCapabilities)
	isNAT := a.plan.network.mode == NetworkPublicInternet
	if isNAT {
		want += len(natCapabilities)
	}
	// Report a missing required operation even when the total count changed.
	for _, cap := range baseCapabilities {
		if !slices.Contains(caps, cap) {
			return fmt.Errorf("%w: GVX control capability %q", ErrCapabilityMissing, cap)
		}
	}
	if isNAT {
		for _, cap := range natCapabilities {
			if !slices.Contains(caps, cap) {
				return fmt.Errorf("%w: GVX control capability %q", ErrCapabilityMissing, cap)
			}
		}
	}
	if len(caps) != want {
		return fmt.Errorf("%w: unexpected GVX capability count %d, want %d", ErrCapabilityMissing, len(caps), want)
	}
	return nil
}

// Done indicates that the control session is no longer usable; unlike the
// supplied Peer.Done, it never proves that the process has exited.
func (a *GVXAdapter) Done() <-chan struct{} { return a.done }

// Err describes terminal session failure or closure, independently of exit.
func (a *GVXAdapter) Err() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return errors.Join(a.err, a.killErr)
}

func (a *GVXAdapter) peerEnded() bool {
	select {
	case <-a.peer.Done:
		return true
	default:
		return false
	}
}

func (a *GVXAdapter) exitStatus() error {
	if a.peer.Exited != nil && !a.peer.Exited() {
		return ErrExitUnconfirmed
	}
	return ErrPeerExited
}

func (a *GVXAdapter) force() {
	a.kill.Do(func() {
		if a.peerEnded() && a.exitStatus() == ErrPeerExited {
			return
		}
		go func() {
			if err := a.peer.Kill(); err != nil {
				a.mu.Lock()
				a.killErr = fmt.Errorf("force owned GVX peer: %w", err)
				a.mu.Unlock()
			}
		}()
	})
}

func (a *GVXAdapter) terminate(cause error, force bool) {
	if force {
		a.force()
	}
	a.finish.Do(func() {
		a.mu.Lock()
		a.err = cause
		a.mu.Unlock()
		close(a.done)
		if a.wire.conn != nil {
			_ = a.wire.conn.Close()
		}
	})
}

func (a *GVXAdapter) connectionLost(err error) {
	if a.peerEnded() && a.exitStatus() == ErrPeerExited {
		a.terminate(ErrPeerExited, false)
	} else {
		a.terminate(fmt.Errorf("%w: %w", ErrControlLost, err), true)
	}
}

func (a *GVXAdapter) drainPeer(cause error) {
	if a.peerEnded() && a.exitStatus() == ErrPeerExited {
		a.terminate(ErrPeerExited, false)
		return
	}
	a.terminate(cause, false)
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	if err := a.waitExit(ctx); err != nil {
		a.force()
	}
}

func (a *GVXAdapter) live() error {
	select {
	case <-a.done:
		return a.Err()
	default:
	}
	if a.peerEnded() {
		err := a.exitStatus()
		a.terminate(err, err == ErrExitUnconfirmed)
		return err
	}
	return nil
}

func (a *GVXAdapter) acquire(ctx context.Context) error {
	select {
	case a.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			a.release()
			return err
		}
		if err := a.live(); err != nil {
			a.release()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-a.done:
		return a.Err()
	}
}

func (a *GVXAdapter) release() { <-a.gate }

// SetEgress rechecks the reviewed run and consumes only its one approved policy.
// No caller-provided rule document can widen it. Concurrent changes serialize
// on this adapter; revocation closes it before reuse is possible.
func (a *GVXAdapter) SetEgress(ctx context.Context, instanceID string, policy EgressPolicy) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	if instanceID != a.plan.identity.InstanceID || policy.Identity != a.plan.identity {
		err := fmt.Errorf("%w: GVX egress identity does not match the reviewed instance", ErrApprovalMismatch)
		// A delayed or foreign decision must never keep an active grant open.
		a.terminate(err, true)
		return err
	}
	if err := a.acquire(ctx); err != nil {
		if !policy.Open {
			a.terminate(err, true)
		}
		return err
	}
	defer a.release()
	if !policy.Open {
		var policyErr error
		if a.plan.network.mode == NetworkPublicInternet {
			policyErr = a.replacePolicy(ctx, json.RawMessage(denyPolicyJSON))
		}
		a.open = false
		a.terminate(errors.Join(ErrEgressRevoked, policyErr), true)
		return errors.Join(policyErr, a.waitExit(ctx))
	}
	err := a.openReviewedPolicy(ctx)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		a.terminate(err, true)
		return err
	}
	a.open = true
	return a.live()
}

func (a *GVXAdapter) openReviewedPolicy(ctx context.Context) error {
	if err := a.verifyLive(ctx); err != nil {
		return err
	}
	if a.plan.network.mode == NetworkNone {
		return nil
	}
	n := a.plan.network
	active := json.RawMessage(denyPolicyJSON)
	if a.open {
		active = n.policy
	}
	if err := a.getPolicy(ctx, active); err != nil {
		return err
	}
	if err := n.verifyHostExclusions(); err != nil {
		return err
	}
	if !a.open {
		if err := a.replacePolicy(ctx, n.policy); err != nil {
			return err
		}
	}
	return a.verifyLive(ctx)
}

// UpdateResources re-applies precisely the approved finite compute limits and
// the network profile's pair of rates. This is not a new approval operation.
func (a *GVXAdapter) UpdateResources(ctx context.Context, limits ResourceLimits) error {
	if limits != a.plan.limits {
		return fmt.Errorf("%w: resource update differs from the reviewed limits", ErrApprovalMismatch)
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	if err := a.acquire(ctx); err != nil {
		return err
	}
	defer a.release()
	request := struct {
		MemoryBytes int64   `json:"memory_bytes"`
		CPUMillis   int64   `json:"cpu_millis"`
		PIDs        int64   `json:"pids_limit"`
		IsolateLAN  *bool   `json:"isolate_lan,omitempty"`
		TXBPS       *uint64 `json:"net_tx_bps,omitempty"`
		RXBPS       *uint64 `json:"net_rx_bps,omitempty"`
	}{MemoryBytes: limits.MemoryBytes, CPUMillis: limits.CPUMillicores, PIDs: limits.MaxPIDs}
	if a.plan.network.mode == NetworkPublicInternet {
		lan := true
		request.IsolateLAN, request.TXBPS, request.RXBPS = &lan, &a.plan.network.tx, &a.plan.network.rx
	}
	var snapshot resourceSnapshot
	err := a.rpc(ctx, "resource.update", request, &snapshot)
	if err == nil {
		err = a.verifyResources(snapshot)
	}
	if err == nil {
		err = a.verifyLive(ctx)
	}
	if err == nil && a.plan.network.mode == NetworkPublicInternet {
		active := json.RawMessage(denyPolicyJSON)
		if a.open {
			active = a.plan.network.policy
		}
		err = a.getPolicy(ctx, active)
	}
	if err != nil {
		a.terminate(err, true)
		return err
	}
	return a.live()
}

// Stop closes egress, requests a bounded guest shutdown, and waits for proof
// from the owned process observer. Missing or ambiguous control acknowledgement
// triggers the out-of-band kill, not a successful cleanup based on socket EOF.
func (a *GVXAdapter) Stop(ctx context.Context, grace time.Duration) error {
	if grace < 0 || grace > maxStopGrace || grace%time.Millisecond != 0 {
		return errors.New("GVX stop grace must be whole milliseconds between zero and one minute")
	}
	if err := a.acquire(ctx); err != nil {
		a.terminate(err, true)
		exitCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		defer cancel()
		return a.waitExit(exitCtx)
	}
	defer a.release()
	var stopErr error
	if a.open && a.plan.network.mode == NetworkPublicInternet {
		denyCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		stopErr = a.replacePolicy(denyCtx, json.RawMessage(denyPolicyJSON))
		cancel()
	}
	a.open = false
	if stopErr == nil {
		a.stopping.Store(true)
		stopCtx, cancel := context.WithTimeout(ctx, grace+requestTimeout)
		var reply struct {
			Signaled string `json:"signaled"`
		}
		stopErr = a.rpc(stopCtx, "lifecycle.stop", struct {
			TimeoutMS int64 `json:"timeout_ms"`
		}{grace.Milliseconds()}, &reply)
		cancel()
		if stopErr == nil && reply.Signaled != "SIGTERM" {
			stopErr = fmt.Errorf("%w: lifecycle.stop returned unexpected signal", ErrControlLost)
		}
	}
	if stopErr != nil {
		a.terminate(stopErr, true)
	}
	exitCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	if err := a.waitExit(exitCtx); err != nil {
		a.terminate(err, true)
		return errors.Join(stopErr, err)
	}
	a.terminate(ErrPeerExited, false)
	if errors.Is(stopErr, ErrPeerExited) {
		return nil
	}
	return stopErr
}

// Close discards the control channel and requests forced shutdown. It does not
// wait: the owner must still observe the child before releasing any lease.
func (a *GVXAdapter) Close() error {
	a.terminate(ErrEgressRevoked, true)
	return nil
}

func (a *GVXAdapter) waitExit(ctx context.Context) error {
	if !a.peerEnded() {
		select {
		case <-a.peer.Done:
		case <-ctx.Done():
			if !a.peerEnded() {
				return errors.Join(ErrExitUnconfirmed, ctx.Err(), a.Err())
			}
		}
	}
	if a.exitStatus() == ErrExitUnconfirmed {
		return errors.Join(ErrExitUnconfirmed, a.Err())
	}
	return nil
}

type resourceSnapshot struct {
	MemoryBytes int64   `json:"memory_bytes"`
	CPUMillis   int64   `json:"cpu_millis"`
	QuotaUSec   int64   `json:"cpu_quota_usec"`
	PeriodUSec  int64   `json:"cpu_period_usec"`
	CPUs        int64   `json:"guest_cpus"`
	PIDs        int64   `json:"pids_limit"`
	IsolateLAN  *bool   `json:"isolate_lan"`
	TXBPS       *uint64 `json:"net_tx_bps"`
	RXBPS       *uint64 `json:"net_rx_bps"`
}

func (a *GVXAdapter) verifyResources(s resourceSnapshot) error {
	l, net := a.plan.limits, a.plan.network
	if s.CPUMillis == 0 || s.QuotaUSec == 0 || s.PeriodUSec == 0 || s.CPUs == 0 ||
		s.PIDs == 0 || s.MemoryBytes == 0 || s.IsolateLAN == nil || s.TXBPS == nil || s.RXBPS == nil {
		return fmt.Errorf("%w: GVX did not report effective guest resources and network shaping", ErrCapabilityMissing)
	}
	if s.MemoryBytes != l.MemoryBytes || s.CPUMillis != l.CPUMillicores || s.QuotaUSec != l.CPUMillicores*100 ||
		s.PeriodUSec != 100_000 || s.CPUs != (l.CPUMillicores+999)/1000 || s.PIDs != l.MaxPIDs ||
		*s.IsolateLAN != (net.mode == NetworkPublicInternet) ||
		*s.TXBPS != net.tx || *s.RXBPS != net.rx {
		return fmt.Errorf("%w: effective GVX limits, LAN isolation, or NAT QoS diverge from the run plan", ErrApprovalMismatch)
	}
	return nil
}

type inspectSnapshot struct {
	ID, Name, State, Platform, Architecture string
	SyscallIsolation                        string            `json:"syscall_isolation"`
	Lockdown                                bool              `json:"lockdown_applied"`
	NetworkMode                             string            `json:"network_mode"`
	Eth0IP                                  string            `json:"eth0_ip"`
	Resources                               resourceSnapshot  `json:"resources"`
	Ports                                   []json.RawMessage `json:"ports"`
	DynamicBindAddrs                        []string          `json:"dynamic_bind_addrs"`
	AutoPublishAddr                         string            `json:"auto_publish_addr"`
	Capabilities                            []string          `json:"capabilities"`
	PIDCount                                int               `json:"pid_count"`
}

func (a *GVXAdapter) inspect(ctx context.Context) (inspectSnapshot, error) {
	var s inspectSnapshot
	if err := a.rpc(ctx, "sandbox.inspect", nil, &s); err != nil {
		return s, err
	}
	p := a.plan
	isolation := "hardware"
	if p.backend == "systrap" {
		isolation = "kernel"
	}
	mode := "none"
	if p.network.mode == NetworkPublicInternet {
		mode = "nat"
	}
	if s.ID != p.sandboxID || s.Name != p.sandboxID || s.Platform != p.backend || s.Architecture != p.target.Arch ||
		!s.Lockdown || s.SyscallIsolation != isolation || s.NetworkMode != mode ||
		len(s.Ports) != 0 || len(s.DynamicBindAddrs) != 0 || s.AutoPublishAddr != "" {
		return s, fmt.Errorf("%w: GVX inspect identity, target, lockdown, or network posture mismatch", ErrApprovalMismatch)
	}
	return s, a.verifyCapabilities(s.Capabilities)
}

func (a *GVXAdapter) verifyRunning(s inspectSnapshot) error {
	if s.State == "exited" {
		return ErrPeerClosing
	}
	if s.State != "running" || s.PIDCount < 1 {
		return fmt.Errorf("%w: GVX sandbox is not running a guest process", ErrCapabilityMissing)
	}
	if a.plan.network.mode == NetworkPublicInternet {
		// v0.22's NAT default is 10.0.2.15; status reports the IP without mask.
		ip, err := netip.ParseAddr(s.Eth0IP)
		if err != nil || ip != netip.AddrFrom4([4]byte{10, 0, 2, 15}) {
			return fmt.Errorf("%w: GVX NAT does not report its pinned IPv4 guest address", ErrApprovalMismatch)
		}
	} else if s.Eth0IP != "" {
		return fmt.Errorf("%w: NONE unexpectedly reports an eth0 address", ErrApprovalMismatch)
	}
	return a.verifyResources(s.Resources)
}

func (a *GVXAdapter) verifyLive(ctx context.Context) error {
	s, err := a.inspect(ctx)
	if err != nil {
		return err
	}
	return a.verifyRunning(s)
}

func (a *GVXAdapter) verifyStartup(ctx context.Context) error {
	for {
		s, err := a.inspect(ctx)
		if err != nil {
			return err
		}
		if s.State == "starting" || s.State == "running" && s.PIDCount == 0 {
			if err := waitStartup(ctx); err != nil {
				return err
			}
			continue
		}
		if err := a.verifyRunning(s); err != nil {
			return err
		}
		break
	}
	if err := a.verifyMounts(ctx); err != nil {
		return err
	}
	if a.plan.network.mode == NetworkPublicInternet {
		return a.getPolicy(ctx, json.RawMessage(denyPolicyJSON))
	}
	return nil
}

func (a *GVXAdapter) verifyMounts(ctx context.Context) error {
	var reply struct {
		Mounts []struct {
			Target, Type, Source string
			ReadOnly             *bool `json:"read_only"`
		} `json:"mounts"`
	}
	if err := a.rpc(ctx, "mount.list", nil, &reply); err != nil {
		return err
	}
	planned := a.plan.mounts
	if len(reply.Mounts) != len(planned) {
		return fmt.Errorf("%w: GVX mount count mismatch", ErrApprovalMismatch)
	}
	for _, m := range planned {
		matches := 0
		for _, actual := range reply.Mounts {
			if actual.Target != m.target {
				continue
			}
			matches++
			if m.kind != "" && m.kind != actual.Type || actual.ReadOnly == nil || *actual.ReadOnly != m.readOnly ||
				m.source != "" && !a.sameMountSource(m.source, actual.Source) {
				return fmt.Errorf("%w: GVX mount %s type, source, or access mismatch", ErrApprovalMismatch, m.target)
			}
		}
		if matches != 1 {
			return fmt.Errorf("%w: GVX mount %s missing or duplicated", ErrApprovalMismatch, m.target)
		}
	}
	return nil
}

func (a *GVXAdapter) sameMountSource(expected, actual string) bool {
	if sameHostPath(a.plan.target, expected, actual) {
		return true
	}
	if !validHostPath(a.plan.target, expected) {
		return false // fixed virtual label, not a host path
	}
	resolved, err := filepath.EvalSymlinks(expected)
	return err == nil && sameHostPath(a.plan.target, actual, resolved)
}

type policyState struct {
	Policy json.RawMessage `json:"policy"`
}

func (a *GVXAdapter) getPolicy(ctx context.Context, expected json.RawMessage) error {
	var state policyState
	if err := a.rpc(ctx, "net.policy_get", nil, &state); err != nil {
		return err
	}
	return verifyPolicy(state.Policy, expected)
}

func (a *GVXAdapter) replacePolicy(ctx context.Context, expected json.RawMessage) error {
	var state policyState
	if err := a.rpc(ctx, "net.policy_set", policyState{Policy: expected}, &state); err != nil {
		return err
	}
	if err := verifyPolicy(state.Policy, expected); err != nil {
		return err
	}
	return a.getPolicy(ctx, expected)
}

func verifyPolicy(actual, expected json.RawMessage) error {
	if len(actual) == 0 || len(actual) > maxPolicyBytes || bytes.Equal(actual, []byte("null")) {
		return fmt.Errorf("%w: GVX reports no active bounded policy", ErrApprovalMismatch)
	}
	if bytes.Equal(actual, expected) {
		return nil
	}
	// The pinned vendor marshals the same typed schema in the same order. A
	// comparison of the complete compact document also rejects unknown or
	// duplicated keys instead of accepting their last decoded values.
	var compact bytes.Buffer
	if err := json.Compact(&compact, actual); err != nil {
		return fmt.Errorf("%w: decode active GVX policy: %w", ErrApprovalMismatch, err)
	}
	if !bytes.Equal(compact.Bytes(), expected) {
		return fmt.Errorf("%w: active GVX firewall differs from approved policy", ErrApprovalMismatch)
	}
	return nil
}
