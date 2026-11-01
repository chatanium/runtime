package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin/runner"
)

// NewRunnerFactory never executes cmd.Path. Only go-plugin's explicit bootstrap
// environment crosses the supervisor boundary; no host process environment does.
type RunnerFactory struct {
	mu     sync.Mutex
	client *Client
	lease  Lease
	runner *dockerRunner
	closed bool
}

func NewRunnerFactory(client *Client, lease Lease) *RunnerFactory {
	return &RunnerFactory{client: client, lease: lease}
}
func (f *RunnerFactory) RunnerFunc(_ hclog.Logger, cmd *exec.Cmd, socketDir string) (runner.Runner, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.runner != nil {
		return nil, invalid("runner factory is single-use")
	}
	client, lease := f.client, f.lease
	if client == nil || cmd == nil || cmd.Path != "" {
		return nil, invalid("RunnerFunc requires an empty command and supervisor client")
	}
	if filepath.Dir(socketDir) != lease.IPCPath || !strings.HasPrefix(filepath.Base(socketDir), "plugin-dir") {
		return nil, invalid("bootstrap socket directory is outside leased IPC")
	}
	env, err := bootstrapEnvironment(cmd.Env, socketDir, lease.SocketGID)
	if err != nil {
		return nil, err
	}
	f.runner = &dockerRunner{client: client, lease: lease, env: env, socketDir: socketDir, sockets: make(map[string]*os.File)}
	return f.runner, nil
}

// CloseTransport MUST follow joining the primary Client()/Start attempt and
// Client.Kill, including its multiplex shutdown. Runner.Kill alone is too early.
func (f *RunnerFactory) CloseTransport() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	if f.runner == nil {
		return nil
	}
	r := f.runner
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	var errs []error
	for _, socket := range r.sockets {
		errs = append(errs, socket.Close())
	}
	r.sockets = nil
	if r.container != nil {
		errs = append(errs, r.container.Stdout.Close(), r.container.Stderr.Close())
	}
	return errors.Join(errs...)
}

type dockerRunner struct {
	mu        sync.Mutex
	client    *Client
	lease     Lease
	env       []string
	socketDir string
	container *Container
	sockets   map[string]*os.File
	closed    bool
}

func (r *dockerRunner) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.container != nil {
		return errors.New("runner already started or closed")
	}
	c, err := r.client.Create(ctx, r.lease.Ownership.InstanceID, r.env, r.socketDir)
	if err != nil {
		return err
	}
	r.container = c
	return r.client.Start(ctx, r.lease.Ownership.InstanceID)
}
func (r *dockerRunner) Diagnose(context.Context) string {
	return "isolated Docker runner; detailed untrusted output is in bounded supervisor logs"
}
func (r *dockerRunner) Name() string { return "flexmodule/" + r.lease.Ownership.InstanceID }
func (r *dockerRunner) ID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.container == nil {
		return ""
	}
	return r.container.ID
}
func (r *dockerRunner) Stdout() io.ReadCloser {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.container == nil {
		return nil
	}
	return r.container.Stdout
}
func (r *dockerRunner) Stderr() io.ReadCloser {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.container == nil {
		return nil
	}
	return r.container.Stderr
}
func (r *dockerRunner) Wait(ctx context.Context) error {
	exit, err := r.client.Wait(ctx, r.lease.Ownership.InstanceID)
	if err != nil {
		return err
	}
	if exit.Code != 0 || exit.OOMKilled {
		return fmt.Errorf("sandbox exit code %d (OOM=%t)", exit.Code, exit.OOMKilled)
	}
	return nil
}
func (r *dockerRunner) Kill(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	// Socket descriptors are intentionally not closed here: go-plugin may still
	// have a primary dial in flight until its outer Client.Kill has joined.
	if err := r.client.Terminate(ctx, r.lease.Ownership.InstanceID); err != nil {
		return err
	}
	r.closed = true
	return nil
}
func (r *dockerRunner) PluginToHost(network, address string) (string, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	guestDir := filepath.Join(GuestIPCPath, filepath.Base(r.socketDir))
	if r.closed || network != "unix" || filepath.Dir(address) != guestDir || strings.ContainsAny(address, "\x00\r\n") {
		return "", "", errors.New("only the owned primary Unix socket is permitted")
	}
	// There is exactly one primary transport. Reverse services use the mandatory
	// gRPC multiplex transport, not additional untrusted broker pathnames.
	if f := r.sockets[address]; f != nil {
		return "unix", fmt.Sprintf("/proc/self/fd/%d", f.Fd()), nil
	}
	if len(r.sockets) != 0 {
		return "", "", errors.New("additional broker socket rejected")
	}
	relative := filepath.Join(filepath.Base(r.socketDir), filepath.Base(address))
	f, err := r.client.CaptureSocket(context.Background(), r.lease.Ownership.InstanceID, relative)
	if err != nil {
		return "", "", err
	}
	r.sockets[address] = f
	return "unix", fmt.Sprintf("/proc/self/fd/%d", f.Fd()), nil
}
func (r *dockerRunner) HostToPlugin(network, address string) (string, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || network != "unix" || filepath.Dir(address) != r.socketDir || strings.ContainsAny(address, "\x00\r\n") {
		return "", "", errors.New("host socket outside owned primary transport")
	}
	guest := filepath.Join(GuestIPCPath, filepath.Base(r.socketDir), filepath.Base(address))
	if r.sockets[guest] == nil {
		return "", "", errors.New("additional host broker socket rejected")
	}
	return "unix", guest, nil
}

func bootstrapEnvironment(input []string, hostDir string, gid uint32) ([]string, error) {
	allowed := map[string]bool{"FLEXMODULE_PLUGIN": true, "PLUGIN_MIN_PORT": true, "PLUGIN_MAX_PORT": true, "PLUGIN_PROTOCOL_VERSIONS": true, "PLUGIN_MULTIPLEX_GRPC": true, "PLUGIN_CLIENT_CERT": true, "PLUGIN_UNIX_SOCKET_GROUP": true, "PLUGIN_UNIX_SOCKET_DIR": true}
	values := make(map[string]string, len(input))
	output := make([]string, 0, len(input)+1)
	for _, entry := range input {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || !allowed[key] || strings.IndexByte(value, 0) >= 0 {
			return nil, invalid("unapproved bootstrap environment")
		}
		if _, exists := values[key]; exists {
			return nil, invalid("duplicate bootstrap variable")
		}
		values[key] = value
	}
	if values["FLEXMODULE_PLUGIN"] != "CHATANIUM_FOREVER" || values["PLUGIN_PROTOCOL_VERSIONS"] != "2" || values["PLUGIN_MULTIPLEX_GRPC"] != "true" || values["PLUGIN_CLIENT_CERT"] == "" || values["PLUGIN_UNIX_SOCKET_DIR"] != hostDir || values["PLUGIN_UNIX_SOCKET_GROUP"] != strconv.FormatUint(uint64(gid), 10) {
		return nil, invalid("mandatory AutoMTLS/multiplex/socket bootstrap is missing")
	}
	values["PLUGIN_UNIX_SOCKET_DIR"] = filepath.Join(GuestIPCPath, filepath.Base(hostDir))
	for _, entry := range input {
		key, _, _ := strings.Cut(entry, "=")
		output = append(output, key+"="+values[key])
	}
	output = append(output, "TMPDIR="+GuestScratchPath)
	return output, nil
}
