// sandbox-module is an explicit integration fixture, never a runtime fallback.
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	plugin "github.com/hashicorp/go-plugin"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

//go:embed manifest.json
var manifestBytes []byte

type probeConfig struct {
	ConnectTimeoutSeconds     int              `json:"connect_timeout_seconds"`
	BlockedTCPAddresses       []string         `json:"blocked_tcp_addresses"`
	ForbiddenEnvironmentNames []string         `json:"forbidden_environment_names"`
	Lifecycle                 *lifecycleConfig `json:"lifecycle,omitempty"`
	Scenario                  *scenarioConfig  `json:"scenario,omitempty"`
	EndpointRace              bool             `json:"endpoint_race,omitempty"`
}
type module struct {
	mu      sync.Mutex
	core    core.CoreClient
	ready   wire.Readiness
	started bool
	config  probeConfig
	probes  *probeSession
	readyAt time.Time
	runCtx  context.Context
	cancel  context.CancelFunc
	done    chan struct{}
}

func (m *module) GetManifest(context.Context) (*wire.ModuleManifest, error) {
	v := new(wire.ModuleManifest)
	if protojson.Unmarshal(manifestBytes, v) != nil {
		return nil, errors.New("invalid embedded manifest")
	}
	return v, nil
}
func (m *module) GetStatus(ctx context.Context) (*wire.Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		m.probes.record("readiness", "cancelled", err, nil)
		return nil, err
	}
	if !m.readyAt.IsZero() {
		// Use the runtime's readiness polling contract rather than occupying a
		// hook RPC for this entire delay and accidentally testing its per-call
		// timeout instead of the cumulative startup deadline.
		if time.Now().Before(m.readyAt) {
			return &wire.Status{Readiness: wire.Readiness_READINESS_NOT_READY}, nil
		}
		m.readyAt = time.Time{}
		if m.config.Lifecycle.FailStage == "readiness" {
			m.ready = wire.Readiness_READINESS_FAILED
			m.probes.record("readiness", "deliberate-failure", nil, nil)
		} else {
			m.probes.record("readiness", "delay-completed", nil, nil)
		}
	}
	return &wire.Status{Readiness: m.ready}, nil
}
func (m *module) OnEvent(context.Context, *wire.EventEnvelope) error {
	return errors.New("sandbox fixture accepts no backend events")
}
func (m *module) OnStage(ctx context.Context, r *wire.StageRequest) error {
	if r == nil {
		return errors.New("missing stage")
	}
	switch r.Stage {
	case wire.Stage_STAGE_INIT:
		if r.InitContext == nil || r.InitContext.Grants == nil || len(r.InitContext.Grants.Backends) != 0 {
			return errors.New("sandbox probe requires backendless authenticated grants and mount paths")
		}
		value, err := m.core.GetConfig(ctx)
		if err != nil {
			return err
		}
		var c probeConfig
		d := json.NewDecoder(bytes.NewReader(value.Json))
		d.DisallowUnknownFields()
		if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
			return errors.New("invalid probe config")
		}
		if err = validateControls(c); err != nil {
			return err
		}
		if err = validateFixtureGrants(c, r.InitContext); err != nil {
			return err
		}
		var session *probeSession
		if c.Lifecycle != nil || c.Scenario != nil {
			session, err = newProbeSession(r.InitContext.PersistentDirectory, r.InitContext.ScratchDirectory)
			if err != nil {
				return err
			}
		}
		m.mu.Lock()
		m.config, m.probes = c, session
		m.mu.Unlock()
		session.record("init", "entered", nil, nil)
		if c.Lifecycle != nil {
			if c.Lifecycle.InitArtifact {
				if err = session.initArtifact(); err != nil {
					return err
				}
			}
			if err = lifecycleStep(ctx, session, "init", c.Lifecycle.InitDelayMS, c.Lifecycle.FailStage); err != nil {
				return err
			}
		}
		if err = probe(ctx, c, r.InitContext.PersistentDirectory, r.InitContext.ScratchDirectory); err != nil {
			session.record("baseline", "returned-error", err, nil)
			m.mu.Lock()
			m.ready = wire.Readiness_READINESS_FAILED
			m.mu.Unlock()
			return err
		}
		session.record("baseline", "returned", nil, nil)
		m.mu.Lock()
		m.ready = wire.Readiness_READINESS_READY
		if c.Lifecycle != nil && (c.Lifecycle.ReadinessDelayMS != 0 || c.Lifecycle.FailStage == "readiness") {
			m.readyAt = time.Now().Add(time.Duration(c.Lifecycle.ReadinessDelayMS) * time.Millisecond)
		}
		m.mu.Unlock()
		return nil
	case wire.Stage_STAGE_START:
		m.mu.Lock()
		if m.ready != wire.Readiness_READINESS_READY || m.started || !m.readyAt.IsZero() {
			m.mu.Unlock()
			return errors.New("probe not ready")
		}
		c, session := m.config, m.probes
		m.mu.Unlock()
		if c.Lifecycle != nil {
			if err := lifecycleStep(ctx, session, "start", c.Lifecycle.StartDelayMS, c.Lifecycle.FailStage); err != nil {
				return err
			}
		}
		m.mu.Lock()
		m.started = true
		if c.Scenario != nil {
			m.runCtx, m.cancel = context.WithCancel(context.Background())
			m.done = make(chan struct{})
			go m.awaitTrigger(m.runCtx, m.done, c.Scenario, session)
		}
		m.mu.Unlock()
		session.record("start", "returned-awaiting-approved-trigger", nil, nil)
		return nil
	case wire.Stage_STAGE_DRAIN, wire.Stage_STAGE_STOP:
		m.mu.Lock()
		cancel, done, session := m.cancel, m.done, m.probes
		m.started = false
		m.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if done != nil {
			select {
			case <-done:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if r.Stage == wire.Stage_STAGE_STOP && session != nil {
			session.cleanupArtifact()
			session.record("stop", "observed", nil, nil)
			session.close()
		}
		return ctx.Err()
	default:
		return errors.New("invalid stage")
	}
}

func probe(ctx context.Context, c probeConfig, persistentDir, scratchDir string) error {
	if c.ConnectTimeoutSeconds < 1 || c.ConnectTimeoutSeconds > 10 || len(c.BlockedTCPAddresses) < 2 || len(c.BlockedTCPAddresses) > 32 || len(c.ForbiddenEnvironmentNames) == 0 || len(c.ForbiddenEnvironmentNames) > 32 {
		return errors.New("finite probe config required")
	}
	if os.Getuid() == 0 || os.Getgid() == 0 {
		return errors.New("module unexpectedly runs as root")
	}
	for _, name := range c.ForbiddenEnvironmentNames {
		if name == "" || strings.ContainsAny(name, "=\x00") {
			return errors.New("invalid forbidden env name")
		}
		if _, ok := os.LookupEnv(name); ok {
			return errors.New("host environment leaked")
		}
	}
	for _, path := range []string{"/run/chatanium/control", "/var/lib/chatanium", "/run/netns"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			return errors.New("native management or IPC path unexpectedly accessible")
		}
	}
	var stat unix.Statfs_t
	if unix.Statfs("/", &stat) != nil || stat.Flags&unix.ST_RDONLY == 0 {
		return errors.New("module root filesystem is not read-only")
	}
	if err := probeStorage(persistentDir, scratchDir); err != nil {
		return err
	}
	ipv4, ipv6 := false, false
	for _, address := range c.BlockedTCPAddresses {
		host, port, err := net.SplitHostPort(address)
		if err != nil || port == "" {
			return errors.New("invalid numeric probe target")
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return errors.New("probe target must have explicit numeric IP")
		}
		if ip.To4() != nil {
			ipv4 = true
		} else {
			ipv6 = true
		}
		if expectedFixtureEgress(c) == wire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET {
			// PUBLIC operations run only after the approved post-START delay.
			// INIT retains baseline validation, not NONE semantics.
			continue
		}
		bounded, cancel := context.WithTimeout(ctx, time.Duration(c.ConnectTimeoutSeconds)*time.Second)
		conn, err := (&net.Dialer{}).DialContext(bounded, "tcp", address)
		cancel()
		if conn != nil {
			conn.Close()
		}
		if err == nil {
			return errors.New("NONE egress unexpectedly connected")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, unix.ENETUNREACH) && !errors.Is(err, unix.EHOSTUNREACH) && !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) {
			return errors.New("network denial inconclusive: target refused or unsupported address")
		}
	}
	if !ipv4 || !ipv6 {
		return errors.New("both IP families must be probed")
	}
	return nil
}

func main() {
	if fixtureProcessMode(os.Args[1:]) {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &module{ready: wire.Readiness_READINESS_NOT_READY}
	p, err := core.NewModulePlugin(ctx, m, func(_ context.Context, conn grpc.ClientConnInterface) error {
		var e error
		m.core, e = core.NewCoreClient(conn, core.JSONLimits{MaxBytes: 256 << 10, MaxDepth: 32})
		return e
	}, core.TransportLimits{MaxReceiveBytes: 4 << 20, MaxSendBytes: 4 << 20})
	if err != nil {
		os.Exit(1)
	}
	defer p.Close()
	plugin.Serve(p.ServeConfig())
}

// probeStorage uses only the authenticated guest paths supplied during INIT.
// Empty paths must not fall through to os.CreateTemp's default host temp path.
func probeStorage(persistentDir, scratchDir string) error {
	if persistentDir == scratchDir {
		return errors.New("persistent and scratch mount paths must be distinct")
	}
	for _, dir := range []string{persistentDir, scratchDir} {
		if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || dir == "/" || strings.ContainsRune(dir, 0) {
			return errors.New("authenticated mount path must be canonical and absolute")
		}
	}
	for _, dir := range []string{persistentDir, scratchDir} {
		f, err := os.CreateTemp(dir, "probe-")
		if err != nil {
			return errors.New("approved mount is not writable")
		}
		name := f.Name()
		_, writeErr := f.Write([]byte("bounded sandbox probe\n"))
		syncErr := f.Sync()
		closeErr := f.Close()
		removeErr := os.Remove(name)
		if writeErr != nil || syncErr != nil || closeErr != nil || removeErr != nil {
			return errors.New("approved mount I/O failed")
		}
	}
	// Persistent sentinel is a real durable restart observation, not host metadata.
	const sentinel = "flexmodule-sandbox-probe-v2\n"
	path := filepath.Join(persistentDir, "probe-state")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	var existing []byte
	if err == nil {
		f := os.NewFile(uintptr(fd), "persistent-sentinel")
		stat, e := f.Stat()
		if e != nil || !stat.Mode().IsRegular() {
			f.Close()
			return errors.New("persistent sentinel must be a regular file")
		}
		existing, e = io.ReadAll(io.LimitReader(f, int64(len(sentinel)+1)))
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			return errors.New("persistent sentinel read failed")
		}
	}
	if os.IsNotExist(err) {
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return errors.New("persistent sentinel create failed")
		}
		_, a := f.WriteString(sentinel)
		b := f.Sync()
		d := f.Close()
		if a != nil || b != nil || d != nil {
			return errors.New("persistent sentinel write failed")
		}
		directory, e := os.Open(persistentDir)
		if e != nil {
			return errors.New("persistent directory open failed")
		}
		a = directory.Sync()
		b = directory.Close()
		if a != nil || b != nil {
			return errors.New("persistent directory sync failed")
		}
	} else if err != nil || string(existing) != sentinel {
		return errors.New("persistent sentinel corrupt or unreadable")
	}
	return nil
}
