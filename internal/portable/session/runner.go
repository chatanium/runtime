package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-plugin/runner"
	"github.com/thirdscam/chatanium/internal/gvxipc"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/portable/process"
)

var _ host.RuntimeHost = (*Client)(nil)
var _ runner.Runner = (*guestRunner)(nil)

func (c *Client) NewRunnerTransport(lease host.Lease) host.RunnerTransport {
	return &runnerFactory{client: c, lease: lease, base: filepath.Dir(c.endpoint)}
}

type runnerFactory struct {
	mu      sync.Mutex
	client  *Client
	lease   host.Lease
	base    string
	runner  *guestRunner
	closed  bool
	cleanup context.Context
}

func (f *runnerFactory) SocketConfig() *plugin.UnixSocketConfig {
	// No host GID or account is necessary. go-plugin creates a private leaf.
	return &plugin.UnixSocketConfig{TempDir: f.base}
}

func (f *runnerFactory) RunnerFunc(_ hclog.Logger, cmd *exec.Cmd, dir string) (runner.Runner, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || filepath.Dir(dir) != f.base || !strings.HasPrefix(filepath.Base(dir), "plugin-dir") {
		return nil, errProtocol
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.runner != nil || cmd == nil || cmd.Path != "" || process.CheckPrivateDir(f.base) != nil {
		_ = os.Remove(dir)
		return nil, errProtocol
	}
	env, err := guestBootstrap(cmd.Env, dir, f.lease.Spec.GID)
	if err != nil {
		_ = os.Remove(dir)
		return nil, err
	}
	life, cancel := context.WithCancel(context.Background())
	r := &guestRunner{client: f.client, id: f.lease.Ownership.InstanceID, dir: dir, bootstrap: env,
		life: life, cancel: cancel, startDone: make(chan struct{}), pumpDone: make(chan struct{})}
	f.runner = r
	return r, nil
}

func (f *runnerFactory) BeginCloseTransport(ctx context.Context) error {
	f.mu.Lock()
	f.closed = true
	f.cleanup = ctx
	r := f.runner
	f.mu.Unlock()
	if r != nil {
		r.closePhysical()
	}
	return nil
}

func (f *runnerFactory) CloseTransport() error {
	f.mu.Lock()
	r, cleanup := f.runner, f.cleanup
	f.mu.Unlock()
	if r == nil {
		return nil
	}
	if cleanup == nil {
		return host.ErrCleanupIncomplete
	}
	for _, done := range []<-chan struct{}{r.startDone, r.pumpDone} {
		select {
		case <-done:
		default:
			select {
			case <-done:
			case <-cleanup.Done():
				return errors.Join(host.ErrCleanupIncomplete, cleanup.Err())
			}
		}
	}
	// go-plugin may already have removed its leaf in Client.Kill.
	if err := os.Remove(r.dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(host.ErrCleanupIncomplete, err)
	}
	return nil
}

func guestBootstrap(input []string, hostDir string, gid uint32) ([]string, error) {
	if gid == 0 || len(input) != 7 {
		return nil, errProtocol
	}
	result := make([]string, 0, 8)
	for _, entry := range input {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || name == plugin.EnvUnixSocketGroup {
			return nil, errProtocol
		}
		if name == plugin.EnvUnixSocketDir {
			if value != hostDir {
				return nil, errProtocol
			}
			entry = plugin.EnvUnixSocketDir + "=" + GuestSocketDir
		}
		switch name {
		case "PLUGIN_MIN_PORT", "PLUGIN_MAX_PORT":
			// go-plugin sets a default TCP port range even with a Runner.
			// The guest uses only its fixed Unix endpoint.
			entry = name + "=0"
		}
		result = append(result, entry)
	}
	result = append(result, plugin.EnvUnixSocketGroup+"="+strconv.FormatUint(uint64(gid), 10))
	if !validBootstrap(result) {
		return nil, errProtocol
	}
	return result, nil
}

func validBootstrap(env []string) bool {
	if len(env) != 8 {
		return false
	}
	var seen uint8
	for _, entry := range env {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || strings.ContainsRune(value, 0) {
			return false
		}
		var bit uint8
		switch name {
		case "FLEXMODULE_PLUGIN":
			bit, ok = 1, value == "CHATANIUM_FOREVER"
		case "PLUGIN_MIN_PORT":
			bit, ok = 2, value == "0"
		case "PLUGIN_MAX_PORT":
			bit, ok = 4, value == "0"
		case "PLUGIN_PROTOCOL_VERSIONS":
			bit, ok = 8, value == "2"
		case "PLUGIN_MULTIPLEX_GRPC":
			bit, ok = 16, value == "true"
		case "PLUGIN_CLIENT_CERT":
			bit, ok = 32, len(value) <= 8<<10 && strings.HasPrefix(value, "-----BEGIN CERTIFICATE-----\n")
		case plugin.EnvUnixSocketDir:
			bit, ok = 64, value == GuestSocketDir
		case plugin.EnvUnixSocketGroup:
			gid, err := strconv.ParseUint(value, 10, 32)
			bit, ok = 128, err == nil && gid != 0 && gid < 1<<32-1 && strconv.FormatUint(gid, 10) == value
		default:
			return false
		}
		if !ok || seen&bit != 0 {
			return false
		}
		seen |= bit
	}
	return true
}

type guestRunner struct {
	client              *Client
	id, dir             string
	bootstrap           []string
	mu                  sync.Mutex
	life                context.Context
	cancel              context.CancelFunc
	listener            net.Listener
	primary             net.Conn
	channel             io.ReadWriteCloser
	handshake           []byte
	guestPath           string
	startDone, pumpDone chan struct{}
	started             bool
}

func (r *guestRunner) Name() string                    { return "flexmodule/" + r.id }
func (r *guestRunner) ID() string                      { return r.id }
func (r *guestRunner) Diagnose(context.Context) string { return "portable guest primary tunnel" }
func (r *guestRunner) Stderr() io.ReadCloser           { return io.NopCloser(bytes.NewReader(nil)) }
func (r *guestRunner) Stdout() io.ReadCloser {
	r.mu.Lock()
	defer r.mu.Unlock()
	return io.NopCloser(bytes.NewReader(r.handshake))
}

func (r *guestRunner) Start(ctx context.Context) (result error) {
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return errProtocol
	}
	r.started = true
	r.mu.Unlock()
	defer close(r.startDone)
	defer func() {
		if result != nil {
			r.closePhysical()
			close(r.pumpDone)
		}
	}()
	start, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.life, cancel)
	defer stop()
	if start.Err() != nil || r.life.Err() != nil {
		return context.Canceled
	}
	// Windows also supports filesystem AF_UNIX on releases with WHPX. The
	// scope is the private parent directory (ACL on Windows), not guest NAT.
	// No nonlocal or unauthenticated TCP listener is required.
	listener, err := listenPlugin(filepath.Join(r.dir, "s"))
	if err != nil {
		return err
	}
	r.mu.Lock()
	if r.life.Err() != nil {
		r.mu.Unlock()
		_ = listener.Close()
		return context.Canceled
	}
	r.listener = listener
	r.mu.Unlock()
	handshake, channel, err := r.client.Open(start, r.id, r.bootstrap)
	r.bootstrap = nil
	if err != nil {
		return err
	}
	guestPath, err := gvxipc.ValidateHandshake(handshake, GuestSocketDir)
	if err != nil {
		_ = channel.Close()
		return err
	}
	r.mu.Lock()
	if r.life.Err() != nil || start.Err() != nil {
		r.mu.Unlock()
		_ = channel.Close()
		return context.Canceled
	}
	r.guestPath, r.handshake, r.channel = guestPath, handshake, channel
	r.mu.Unlock()
	go r.forward(listener, channel)
	return nil
}

func (r *guestRunner) forward(listener net.Listener, ch io.ReadWriteCloser) {
	defer close(r.pumpDone)
	conn, err := listener.Accept()
	if err != nil {
		_ = ch.Close()
		return
	}
	r.mu.Lock()
	if r.life.Err() != nil {
		r.mu.Unlock()
		_ = conn.Close()
		return
	}
	r.primary = conn
	r.mu.Unlock()
	// The primary connection owns go-plugin's grpc broker multiplexer; no
	// independently dialable service or server port is ever exported.
	_ = listener.Close()
	pump(conn, ch)
}

func (r *guestRunner) PluginToHost(network, address string) (string, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if network != "unix" || address != r.guestPath || r.listener == nil || r.life.Err() != nil {
		return "", "", errProtocol
	}
	return r.listener.Addr().Network(), r.listener.Addr().String(), nil
}

func (r *guestRunner) HostToPlugin(string, string) (string, string, error) {
	return "", "", errProtocol
}

func (r *guestRunner) Wait(ctx context.Context) error {
	wait, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.life, cancel)
	defer stop()
	if r.life.Err() != nil {
		return nil
	}
	exit, err := r.client.Wait(wait, r.id)
	if r.life.Err() != nil {
		return nil
	}
	r.closePhysical()
	if err == nil && (exit.Kind != "exit" || exit.Value != 0 || exit.OOMKilled) {
		err = errors.New("portable guest exited unsuccessfully")
	}
	return err
}

func (r *guestRunner) Kill(context.Context) error {
	// Manager independently calls and verifies supervisor Terminate/Release.
	// Break the mux, which may otherwise hold go-plugin's client mutex.
	r.closePhysical()
	return nil
}

func (r *guestRunner) closePhysical() {
	r.cancel()
	r.mu.Lock()
	listener, primary, channel := r.listener, r.primary, r.channel
	r.listener, r.primary, r.channel = nil, nil, nil
	if !r.started {
		r.started = true
		close(r.startDone)
		close(r.pumpDone)
	}
	r.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	if primary != nil {
		_ = primary.Close()
	}
	if channel != nil {
		_ = channel.Close()
	}
}
