//go:build linux

package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	plugin "github.com/hashicorp/go-plugin"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin/runner"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/gvxipc"
	sharedhost "github.com/thirdscam/chatanium/internal/host"
	"golang.org/x/sys/unix"
)

type RunnerFactory struct {
	mu     sync.Mutex
	client *Client
	lease  sharedhost.Lease
	runner *gvxRunner
	closed bool
}

func NewRunnerFactory(client *Client, lease sharedhost.Lease) *RunnerFactory {
	return &RunnerFactory{client: client, lease: lease}
}
func (c *Client) NewRunnerTransport(lease sharedhost.Lease) sharedhost.RunnerTransport {
	return NewRunnerFactory(c, lease)
}

func (f *RunnerFactory) SocketConfig() *plugin.UnixSocketConfig {
	return &plugin.UnixSocketConfig{TempDir: f.lease.BootstrapPath, Group: strconv.FormatUint(uint64(f.lease.SocketGID), 10)}
}

func (f *RunnerFactory) RunnerFunc(_ hclog.Logger, cmd *exec.Cmd, socketDir string) (runner.Runner, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.runner != nil {
		return nil, invalid("runner factory is single-use")
	}
	if f.client == nil || cmd == nil || cmd.Path != "" {
		return nil, invalid("RunnerFunc requires empty command and supervisor client")
	}
	base := f.lease.BootstrapPath
	if !filepath.IsAbs(base) || filepath.Clean(base) != base ||
		filepath.Clean(socketDir) != socketDir || filepath.Dir(socketDir) != base ||
		!strings.HasPrefix(filepath.Base(socketDir), "plugin-dir") ||
		strings.ContainsAny(socketDir, "\x00\r\n") {
		return nil, invalid("bootstrap directory is outside the dedicated leased bootstrap root")
	}
	env, err := bootstrapEnvironment(cmd.Env, socketDir, f.lease.SocketGID, f.lease.Spec.GID)
	if err != nil {
		return nil, err
	}
	limits := gvxipc.Limits{
		ControlMessageMaxBytes: f.lease.Spec.Resources.ControlMessageMaxBytes,
		LogBufferBytes:         f.lease.Spec.Resources.LogBufferBytes,
	}
	if err = gvxipc.Workspace(limits); err != nil {
		return nil, err
	}
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(pidfd)
	hr, hw, err := os.Pipe()
	if err != nil {
		unix.Close(pidfd)
		return nil, err
	}
	dr, dw, err := os.Pipe()
	if err != nil {
		hr.Close()
		hw.Close()
		unix.Close(pidfd)
		return nil, err
	}
	r := &gvxRunner{
		client: f.client, lease: f.lease, env: env, limits: limits,
		handshakeReader: hr, handshakeWriter: hw,
		diagnosticReader: dr, diagnosticWriter: dw,
		pidfd: os.NewFile(uintptr(pidfd), "worker-self-pidfd"),
		pid:   os.Getpid(), uid: uint32(os.Geteuid()), gid: uint32(os.Getegid()),
		startDone: make(chan struct{}), done: make(chan struct{}),
		opened: make(chan struct{}), exited: make(chan struct{}), receiveDone: make(chan struct{}),
		guestDir: filepath.Join("/tmp", filepath.Base(socketDir)),
	}
	f.runner = r
	return r, nil
}
func (f *RunnerFactory) BeginCloseTransport(ctx context.Context) error {
	f.mu.Lock()
	f.closed = true
	r := f.runner
	f.mu.Unlock()
	if r != nil {
		r.beginClose(ctx)
	}
	return nil
}
func (f *RunnerFactory) CloseTransport() error {
	f.mu.Lock()
	r := f.runner
	f.mu.Unlock()
	if r == nil {
		return nil
	}
	r.mu.Lock()
	closing := r.closing
	ctx := r.cleanup
	closed, prior := r.pinsClosed, r.closeErr
	r.mu.Unlock()
	if closed {
		return prior
	}
	if !closing || ctx == nil {
		return errors.New("BeginCloseTransport must precede joined consumers and CloseTransport")
	}
	if e := joinTransport(ctx, r.startDone); e != nil {
		return errors.Join(sharedhost.ErrCleanupIncomplete, e)
	}
	if e := joinTransport(ctx, r.done); e != nil {
		return errors.Join(sharedhost.ErrCleanupIncomplete, e)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pinsClosed {
		return r.closeErr
	}
	r.pinsClosed = true
	var errs []error
	if r.stage != nil {
		errs = append(errs, r.stage.Listener.Close(), r.stage.Endpoint.Close())
	}
	errs = append(errs, r.pidfd.Close())
	_ = r.handshakeReader.Close()
	_ = r.diagnosticReader.Close()
	r.closeErr = errors.Join(errs...)
	if r.cleanupCancel != nil {
		r.cleanupCancel()
	}
	return r.closeErr
}

func joinTransport(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	default:
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type gvxRunner struct {
	mu                                                                   sync.Mutex
	client                                                               *Client
	lease                                                                sharedhost.Lease
	env                                                                  []string
	limits                                                               gvxipc.Limits
	stage                                                                *StageProcess
	codec                                                                *gvxipc.Codec
	listener                                                             *net.UnixListener
	connection                                                           *net.UnixConn
	handshakeReader, handshakeWriter, diagnosticReader, diagnosticWriter *os.File
	pidfd                                                                *os.File
	pid                                                                  int
	uid, gid                                                             uint32
	guestDir, guestSocket                                                string
	started, closing, pinsClosed                                         bool
	startup                                                              context.Context
	startupCancel                                                        context.CancelFunc
	startupStop                                                          func() bool
	cleanup                                                              context.Context
	cleanupCancel                                                        context.CancelFunc
	startDone, done, opened, exited, receiveDone                         chan struct{}
	pumps                                                                sync.WaitGroup
	closeOnce, exitOnce, openOnce                                        sync.Once
	protocolErr, closeErr                                                error
	childExit                                                            *gvxipc.ExitPayload
}

func (r *gvxRunner) Name() string { return "flexmodule/" + r.lease.Ownership.InstanceID }
func (r *gvxRunner) ID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stage == nil {
		return ""
	}
	return r.stage.Unit.Name + "/" + r.stage.Unit.InvocationID
}
func (r *gvxRunner) Stdout() io.ReadCloser { return r.handshakeReader }
func (r *gvxRunner) Stderr() io.ReadCloser { return r.diagnosticReader }
func (r *gvxRunner) Diagnose(context.Context) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.protocolErr != nil {
		return "gvx bridge transport failed; bounded diagnostics retained"
	}
	return "gvx isolated stdio transport"
}
func (r *gvxRunner) Start(ctx context.Context) (err error) {
	r.mu.Lock()
	if r.started || r.closing {
		r.mu.Unlock()
		return errors.New("runner already started or closing")
	}
	r.started = true
	r.mu.Unlock()
	defer close(r.startDone)
	pumpsStarted := false
	defer func() {
		if err != nil {
			r.fail(err)
		}
		if !pumpsStarted {
			close(r.done)
		}
	}()
	deadline, ok := ctx.Deadline()
	var now unix.Timespec
	if e := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); e != nil {
		return e
	}
	remaining := r.lease.StartupDeadlineBootNS - now.Nano()
	if remaining <= 0 {
		return context.DeadlineExceeded
	}
	leaseDeadline := time.Now().Add(time.Duration(remaining))
	if !ok || leaseDeadline.Before(deadline) {
		deadline = leaseDeadline
	}
	startup, cancel := context.WithDeadline(context.Background(), deadline)
	r.mu.Lock()
	r.startup = startup
	r.startupCancel = cancel
	r.mu.Unlock()
	callCtx, callCancel := context.WithDeadline(ctx, deadline)
	defer callCancel()
	stage, e := r.client.Create(callCtx, r.lease.Ownership.InstanceID, r.env)
	if e != nil {
		return e
	}
	pipeErr := prepareStagePipes(stage)
	r.mu.Lock()
	r.stage = stage
	closing := r.closing
	r.mu.Unlock()
	if closing {
		r.closePhysical()
		return errors.New("runner closed during Create")
	}
	if pipeErr != nil {
		return pipeErr
	}
	payload, e := gvxipc.ValidateInit(stage.Init, r.limits.Control())
	if e != nil {
		return e
	}
	if stage.Init.SocketDir != r.guestDir || stage.Init.UID != r.lease.Spec.UID || stage.Init.GID != r.lease.Spec.GID || payload.RuntimeInstallationID != r.lease.Ownership.RuntimeInstallationID || payload.EpochID != r.lease.Ownership.EpochID || payload.InstanceID != r.lease.Ownership.InstanceID {
		return errors.New("approved INIT differs from lease binding")
	}
	codec, e := gvxipc.NewCodec(stage.Stdout, stage.Stdin, gvxipc.Host, r.limits)
	if e != nil {
		return e
	}
	ln, e := net.FileListener(stage.Listener)
	if e != nil {
		return e
	}
	listener, ok := ln.(*net.UnixListener)
	if !ok {
		ln.Close()
		return errors.New("native endpoint is not Unix")
	}
	listener.SetUnlinkOnClose(false)
	logs, e := newLogRotation(r.lease.LogPath, r.lease.Spec.Resources.LogFileMaxBytes, r.lease.Spec.Resources.LogRetainedFiles)
	if e != nil {
		listener.Close()
		return e
	}
	r.mu.Lock()
	r.codec = codec
	r.listener = listener
	closing = r.closing
	r.mu.Unlock()
	if closing {
		logs.Close()
		r.closePhysical()
		return errors.New("runner closed before pumps")
	}
	stop := context.AfterFunc(startup, func() { r.fail(context.DeadlineExceeded) })
	r.mu.Lock()
	r.startupStop = stop
	r.mu.Unlock()
	r.pumps.Add(3)
	pumpsStarted = true
	go func() {
		defer r.pumps.Done()
		defer close(r.receiveDone)
		if e := r.receive(); e != nil {
			r.fail(e)
		}
	}()
	go func() {
		defer r.pumps.Done()
		if e := r.accept(); e != nil {
			r.fail(e)
		}
	}()
	go func() {
		defer r.pumps.Done()
		defer logs.Close()
		defer r.diagnosticWriter.Close()
		slab := make([]byte, gvxipc.LogSlab)
		for {
			n, e := stage.Stderr.Read(slab)
			if n > 0 {
				if _, err := logs.Write(slab[:n]); err != nil {
					r.fail(err)
					return
				}
				if _, err := r.diagnosticWriter.Write(slab[:n]); err != nil {
					r.fail(err)
					return
				}
			}
			if e != nil {
				if e != io.EOF {
					r.fail(e)
				}
				return
			}
		}
	}()
	go func() { r.pumps.Wait(); close(r.done) }()
	// No wait for the synthetic handshake reader: go-plugin starts consuming it
	// only after Start returns. Gate release and pumps are the complete contract.
	return r.client.Start(callCtx, r.lease.Ownership.InstanceID)
}
func (r *gvxRunner) receive() error {
	r.mu.Lock()
	c, stage, startup := r.codec, r.stage, r.startup
	r.mu.Unlock()
	if err := c.SendMagic(); err != nil {
		return err
	}
	if err := c.ReadMagic(); err != nil {
		return err
	}
	init, err := json.Marshal(stage.Init)
	if err != nil {
		return err
	}
	if err = c.Write(gvxipc.Init, init); err != nil {
		return err
	}
	nativeClosed := false
	for {
		typ, payload, err := c.Read()
		if err != nil {
			if err == io.EOF && c.Exited() {
				return nil
			}
			return err
		}
		switch typ {
		case gvxipc.RootsReady:
			var result gvxcontract.RootInitResult
			if err = gvxcontract.DecodeStrict(payload, cLimit(r), 16, &result); err != nil {
				return bridgeProtocolError(err)
			}
			if err = gvxipc.ValidateRootResult(stage.Init.Roots, result, cLimit(r)); err != nil {
				return bridgeProtocolError(err)
			}
			if err = r.client.ConfirmGuestStorage(startup, r.lease.Ownership.InstanceID, result); err != nil {
				return err
			}
			if err = c.Write(gvxipc.RootsCommit, nil); err != nil {
				return err
			}
		case gvxipc.Handshake:
			path, err := gvxipc.ValidateHandshake(payload, r.guestDir)
			if err != nil {
				return bridgeProtocolError(err)
			}
			r.mu.Lock()
			r.guestSocket = path
			r.mu.Unlock()
			if err = writeRunnerFull(r.handshakeWriter, payload); err != nil {
				return err
			}
			r.handshakeWriter.Close()
		case gvxipc.OpenOK:
			r.mu.Lock()
			stop := r.startupStop
			r.mu.Unlock()
			if stop != nil {
				stop()
			}
			r.openOnce.Do(func() { close(r.opened) })
		case gvxipc.Data, gvxipc.Fin:
			r.mu.Lock()
			conn := r.connection
			r.mu.Unlock()
			if conn == nil {
				return bridgeProtocolError(errors.New("payload before authenticated native client"))
			}
			if nativeClosed {
				continue
			}
			if typ == gvxipc.Data {
				err = writeRunnerFull(conn, payload)
			} else {
				err = conn.CloseWrite()
			}
			if err == nil {
				continue
			}
			if !errors.Is(err, unix.EPIPE) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
				return err
			}
			// The consumer may close concurrently with the child's exit. Keep
			// validating the stream, without queues, for one finite budget.
			// Only a complete EXIT and the independent unit result can make
			// this race successful; premature EOF remains a transport error.
			nativeClosed = true
			_ = stage.Stdout.SetReadDeadline(time.Now().Add(r.client.Timeout()))
			_ = conn.SetReadDeadline(time.Now())
		case gvxipc.Exit:
			exit, err := gvxipc.DecodeExit(payload, cLimit(r))
			if err != nil {
				return err
			}
			r.mu.Lock()
			r.childExit = &exit
			conn, listener, stop := r.connection, r.listener, r.startupStop
			r.mu.Unlock()
			r.exitOnce.Do(func() { close(r.exited) })
			if stop != nil {
				stop()
			}
			_ = stage.Stdin.SetWriteDeadline(time.Now())
			r.handshakeWriter.Close()
			if conn != nil {
				conn.Close()
			}
			if listener != nil {
				listener.SetDeadline(time.Now())
			}
			select {
			case <-r.opened:
			default:
				return errors.New("guest exited before startup transport completed")
			}
		case gvxipc.Error:
			failure, err := gvxipc.DecodeError(payload, cLimit(r))
			if err != nil {
				return err
			}
			return fmt.Errorf("guest bridge error %s", failure.Code)
		default:
			return bridgeProtocolError(errors.New("unexpected host input frame"))
		}
	}
}

func bridgeProtocolError(err error) error {
	return fmt.Errorf("%w: %v", gvxipc.ErrInvalidFrame, err)
}
func cLimit(r *gvxRunner) int { return r.limits.Control() }
func writeRunnerFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, e := w.Write(p)
		if e != nil {
			return e
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
func (r *gvxRunner) accept() error {
	r.mu.Lock()
	ln, startup := r.listener, r.startup
	r.mu.Unlock()
	if deadline, ok := startup.Deadline(); ok {
		ln.SetDeadline(deadline)
	}
	conn, err := ln.AcceptUnix()
	if err != nil {
		select {
		case <-r.exited:
			return nil
		default:
			return err
		}
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		conn.Close()
		return err
	}
	var authErr error
	err = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			authErr = err
			return
		}
		if int(cred.Pid) != r.pid || cred.Uid != r.uid || cred.Gid != r.gid {
			authErr = errors.New("native client peer is not the registered worker")
			return
		}
		authErr = unix.PidfdSendSignal(int(r.pidfd.Fd()), 0, nil, 0)
	})
	if err != nil || authErr != nil {
		conn.Close()
		return errors.Join(err, authErr)
	}
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		conn.Close()
		return nil
	}
	r.connection = conn
	c := r.codec
	r.mu.Unlock()
	ln.Close() // Exactly one native client; the separate listener pin stays held.
	if err = c.Write(gvxipc.Open, nil); err != nil {
		return r.sendResult(err)
	}
	select {
	case <-r.opened:
	case <-r.exited:
		return nil
	case <-startup.Done():
		return startup.Err()
	}
	slab := make([]byte, gvxipc.MaxData)
	for {
		n, err := conn.Read(slab)
		if n > 0 {
			if c.Exited() {
				return nil
			}
			if sendErr := c.Write(gvxipc.Data, slab[:n]); sendErr != nil {
				return r.sendResult(sendErr)
			}
		}
		if err != nil {
			if c.Exited() {
				return nil
			}
			if err == io.EOF {
				return r.sendResult(c.Write(gvxipc.Fin, nil))
			}
			return r.sendResult(err)
		}
	}
}

// A pipe close can win scheduling against the already-written EXIT. Only a
// validated EXIT (never raw EOF, absent unit evidence or a timeout) makes that
// send race expected; a receive-side protocol error remains authoritative.
func (r *gvxRunner) sendResult(err error) error {
	if err == nil {
		return nil
	}
	select {
	case <-r.exited:
		return nil
	default:
	}
	if !errors.Is(err, unix.EPIPE) && !errors.Is(err, os.ErrClosed) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	budget := r.client.Timeout()
	if budget <= 0 {
		budget = 5 * time.Second
	}
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case <-r.exited:
		return nil
	case <-r.receiveDone:
		r.mu.Lock()
		protocolErr, child := r.protocolErr, r.childExit
		r.mu.Unlock()
		if protocolErr != nil {
			return protocolErr
		}
		if child != nil {
			return nil
		}
		return err
	case <-timer.C:
		return err
	}
}
func (r *gvxRunner) closePhysical() {
	r.mu.Lock()
	stage, conn, ln := r.stage, r.connection, r.listener
	stop, cancel := r.startupStop, r.startupCancel
	r.mu.Unlock()
	if stop != nil {
		stop()
	}
	if cancel != nil {
		cancel()
	}
	if ln != nil {
		ln.SetDeadline(time.Now())
		ln.Close()
	}
	if conn != nil {
		conn.SetDeadline(time.Now())
		conn.Close()
	}
	if stage != nil {
		stage.Stdin.Close()
		stage.Stdout.Close()
		stage.Stderr.Close()
	}
	r.handshakeWriter.Close()
	r.diagnosticWriter.Close()
}
func (r *gvxRunner) beginClose(ctx context.Context) {
	r.closeOnce.Do(func() {
		budget := r.client.Timeout()
		if budget <= 0 {
			budget = 5 * time.Second
		}
		if d, ok := ctx.Deadline(); ok && ctx.Err() == nil {
			if n := time.Until(d); n > 0 && n < budget {
				budget = n
			}
		}
		cleanup, cancel := context.WithTimeout(context.Background(), budget)
		r.mu.Lock()
		r.closing = true
		r.cleanup = cleanup
		r.cleanupCancel = cancel
		started := r.started
		r.mu.Unlock()
		r.closePhysical()
		if !started {
			close(r.startDone)
			close(r.done)
		}
	})
}
func (r *gvxRunner) fail(err error) {
	if err == nil {
		return
	}
	r.mu.Lock()
	closing := r.closing
	if closing && !errors.Is(err, gvxipc.ErrInvalidFrame) {
		r.mu.Unlock()
		return
	}
	if r.protocolErr == nil {
		r.protocolErr = err
	}
	r.mu.Unlock()
	if closing {
		return
	}
	r.beginClose(context.Background())
	r.mu.Lock()
	ctx := r.cleanup
	r.mu.Unlock()
	_ = r.client.Terminate(ctx, r.lease.Ownership.InstanceID)
}
func (r *gvxRunner) Wait(ctx context.Context) error {
	exit, e := r.client.Wait(ctx, r.lease.Ownership.InstanceID)
	if e != nil {
		return e
	}
	if exit.Kind != "exit" && exit.Kind != "signal" || exit.Kind == "exit" && exit.Value > 255 || exit.Kind == "signal" && (exit.Value < 1 || exit.Value > 64) {
		return errors.New("UNKNOWN native exit result")
	}
	r.mu.Lock()
	closing, done := r.closing, r.done
	r.mu.Unlock()
	if !closing {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	r.mu.Lock()
	child, protocolErr := r.childExit, r.protocolErr
	closing = r.closing
	r.mu.Unlock()
	var nativeErr, childErr, missingErr error
	if exit.Kind != "exit" || exit.Value != 0 || exit.OOMKilled {
		nativeErr = fmt.Errorf("sandbox %s %d (OOM=%t)", exit.Kind, exit.Value, exit.OOMKilled)
	}
	if child != nil && (child.Kind != "exit" || child.Value != 0) {
		childErr = fmt.Errorf("guest %s %d", child.Kind, child.Value)
	}
	if !closing && child == nil {
		missingErr = errors.New("native exit without complete bridge EXIT")
	}
	return errors.Join(protocolErr, nativeErr, childErr, missingErr)
}
func (r *gvxRunner) Kill(ctx context.Context) error {
	return r.client.Terminate(ctx, r.lease.Ownership.InstanceID)
}
func (r *gvxRunner) PluginToHost(network, address string) (string, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing || r.stage == nil || network != "unix" || address != r.guestSocket || r.guestSocket == "" {
		return "", "", errors.New("only exact primary Unix handshake endpoint permitted")
	}
	return "unix", fmt.Sprintf("/proc/self/fd/%d", r.stage.Endpoint.Fd()), nil
}
func (r *gvxRunner) HostToPlugin(string, string) (string, string, error) {
	return "", "", errors.New("HostToPlugin forbidden; reverse services require multiplex transport")
}

func bootstrapEnvironment(input []string, hostDir string, hostGID, guestGID uint32) ([]string, error) {
	allowed := map[string]bool{"FLEXMODULE_PLUGIN": true, "PLUGIN_MIN_PORT": true, "PLUGIN_MAX_PORT": true, "PLUGIN_PROTOCOL_VERSIONS": true, "PLUGIN_MULTIPLEX_GRPC": true, "PLUGIN_CLIENT_CERT": true, "PLUGIN_UNIX_SOCKET_GROUP": true, "PLUGIN_UNIX_SOCKET_DIR": true}
	values := make(map[string]string, len(input))
	output := make([]string, 0, len(input))
	for _, entry := range input {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || !allowed[key] || strings.IndexByte(value, 0) >= 0 {
			return nil, invalid("unapproved bootstrap environment")
		}
		if _, ok := values[key]; ok {
			return nil, invalid("duplicate bootstrap variable")
		}
		values[key] = value
	}
	if values["FLEXMODULE_PLUGIN"] != "CHATANIUM_FOREVER" || values["PLUGIN_PROTOCOL_VERSIONS"] != "2" || values["PLUGIN_MULTIPLEX_GRPC"] != "true" || values["PLUGIN_CLIENT_CERT"] == "" || values["PLUGIN_UNIX_SOCKET_DIR"] != hostDir || values["PLUGIN_UNIX_SOCKET_GROUP"] != strconv.FormatUint(uint64(hostGID), 10) {
		return nil, invalid("mandatory AutoMTLS/multiplex/socket bootstrap missing")
	}
	values["PLUGIN_UNIX_SOCKET_DIR"] = filepath.Join("/tmp", filepath.Base(hostDir))
	values["PLUGIN_UNIX_SOCKET_GROUP"] = strconv.FormatUint(uint64(guestGID), 10)
	for _, entry := range input {
		key, _, _ := strings.Cut(entry, "=")
		output = append(output, key+"="+values[key])
	}
	return output, nil
}

// A received blocking FIFO must get a fresh pollable os.File wrapper before
// pumps start. Closing a blocking wrapper during Read/Write can itself wait,
// which would defeat phase-one transport unblocking.
func prepareStagePipes(p *StageProcess) error {
	for i, slot := range []**os.File{&p.Stdin, &p.Stdout, &p.Stderr} {
		old := *slot
		fd, e := unix.FcntlInt(old.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if e != nil {
			return e
		}
		if e = unix.SetNonblock(fd, true); e != nil {
			unix.Close(fd)
			return e
		}
		replacement := os.NewFile(uintptr(fd), old.Name())
		if replacement == nil {
			unix.Close(fd)
			return errors.New("cannot wrap stage pipe")
		}
		if i == 0 {
			e = replacement.SetWriteDeadline(time.Time{})
		} else {
			e = replacement.SetReadDeadline(time.Time{})
		}
		if e != nil {
			replacement.Close()
			return e
		}
		*slot = replacement
		old.Close()
	}
	return nil
}
