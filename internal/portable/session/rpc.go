package session

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxipc"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/portable/process"
)

// Backend binds the exact worker instance ID to the active supervisor epoch.
// Open carries only the authenticated guest handshake and primary plugin bytes.
// Its channel remains open after the startup context expires; Close must wake
// blocked reads and writes. The supervisor owns actual child/lease settlement.
type Backend interface {
	Manifest(ctx context.Context, digest string) ([]byte, error)
	Acquire(ctx context.Context, spec host.LaunchSpec) (host.Lease, error)
	Open(ctx context.Context, instance string, bootstrap []string) ([]byte, io.ReadWriteCloser, error)
	SetEgress(ctx context.Context, instance string, policy host.EgressPolicy) error
	Wait(ctx context.Context, instance string) (host.ProcessExit, error)
	Terminate(ctx context.Context, instance string) error
	Release(ctx context.Context, instance string) error
	Reconcile(ctx context.Context) error
}

const (
	rpcMagic        = "CTSESS02"
	authTimeout     = 5 * time.Second
	maxCallTime     = 10 * time.Minute
	maxRequests     = 4 * maxModules
	maxRequestBytes = gvxipc.MaxControl
)

type operation uint8

const (
	manifest operation = iota + 1
	acquire
	open
	setEgress
	wait
	terminate
	release
	reconcile
)

type request struct {
	Op        operation         `json:"op"`
	Deadline  time.Time         `json:"deadline,omitzero"`
	Digest    string            `json:"digest,omitempty"`
	Spec      *host.LaunchSpec  `json:"spec,omitempty"`
	Instance  string            `json:"instance,omitempty"`
	Bootstrap []string          `json:"bootstrap,omitempty"`
	Policy    host.EgressPolicy `json:"policy,omitempty"`
}

type response struct {
	Error     string            `json:"error,omitempty"`
	Manifest  []byte            `json:"manifest,omitempty"`
	Lease     *host.Lease       `json:"lease,omitempty"`
	Handshake []byte            `json:"handshake,omitempty"`
	Exit      *host.ProcessExit `json:"exit,omitempty"`
}

func (r request) valid() bool {
	if r.Op < manifest || r.Op > reconcile || (r.Op == manifest) != (r.Digest != "") || (r.Op == acquire) != (r.Spec != nil) || (r.Op == open) != (len(r.Bootstrap) > 0) || (r.Op == setEgress) != (r.Policy != "") {
		return false
	}
	if r.Op >= open && r.Op <= release {
		if !lowercaseHex(r.Instance, 16) {
			return false
		}
	} else if r.Instance != "" {
		return false
	}
	switch r.Op {
	case manifest:
		return strings.HasPrefix(r.Digest, "record:sha256:") && lowercaseHex(strings.TrimPrefix(r.Digest, "record:sha256:"), 32)
	case acquire:
		return lowercaseHex(r.Spec.InstanceID, 16)
	case open:
		return validBootstrap(r.Bootstrap)
	case setEgress:
		return r.Policy == host.EgressNone || r.Policy == host.EgressPublicInternet
	}
	return true
}

func (r response) valid(op operation) bool {
	if r.Error != "" {
		return r.Manifest == nil && r.Lease == nil && r.Handshake == nil && r.Exit == nil
	}
	return len(r.Handshake) <= gvxipc.MaxControl && (op == manifest) == (r.Manifest != nil) && (op == acquire) == (r.Lease != nil) && (op == open) == (len(r.Handshake) > 0) && (op == wait) == (r.Exit != nil)
}

type authentication struct {
	epoch string
	key   [maxTokenLength]byte
}

func newAuthentication(creds Credentials) (authentication, error) {
	if !creds.valid() {
		return authentication{}, errProtocol
	}
	a := authentication{epoch: creds.Epoch}
	_, err := hex.Decode(a.key[:], []byte(creds.Token))
	return a, err
}

func (a authentication) proof(role byte, hello, serverNonce []byte) []byte {
	m := hmac.New(sha256.New, a.key[:])
	_, _ = m.Write([]byte{role})
	_, _ = m.Write(hello)
	_, _ = m.Write(serverNonce)
	return m.Sum(nil)
}

func (a authentication) authenticate(conn net.Conn, client bool) error {
	const fixed = len(rpcMagic) + 2
	var hello [fixed + maxEpochLength + sha256.Size]byte
	var challenge [2 * sha256.Size]byte
	if client {
		end := fixed + len(a.epoch)
		copy(hello[:], rpcMagic)
		binary.BigEndian.PutUint16(hello[len(rpcMagic):], uint16(len(a.epoch)))
		copy(hello[fixed:], a.epoch)
		msg := hello[:end+sha256.Size]
		if _, err := rand.Read(msg[end:]); err != nil {
			return err
		}
		if err := writeAll(conn, msg); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, challenge[:]); err != nil {
			return err
		}
		if !hmac.Equal(challenge[sha256.Size:], a.proof('S', msg, challenge[:sha256.Size])) {
			return errProtocol
		}
		return writeAll(conn, a.proof('W', msg, challenge[:sha256.Size]))
	}
	if _, err := io.ReadFull(conn, hello[:fixed]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(hello[len(rpcMagic):]))
	if string(hello[:len(rpcMagic)]) != rpcMagic || n != len(a.epoch) {
		return errProtocol
	}
	msg := hello[:fixed+n+sha256.Size]
	if _, err := io.ReadFull(conn, msg[fixed:]); err != nil {
		return err
	}
	if string(hello[fixed:fixed+n]) != a.epoch {
		return errProtocol
	}
	if _, err := rand.Read(challenge[:sha256.Size]); err != nil {
		return err
	}
	copy(challenge[sha256.Size:], a.proof('S', msg, challenge[:sha256.Size]))
	if err := writeAll(conn, challenge[:]); err != nil {
		return err
	}
	var proof [sha256.Size]byte
	if _, err := io.ReadFull(conn, proof[:]); err != nil {
		return err
	}
	if !hmac.Equal(proof[:], a.proof('W', msg, challenge[:sha256.Size])) {
		return errProtocol
	}
	return nil
}

// Serve owns listener and joins every accepted call on cancellation. Wait and
// Open have independent streams so neither can serialize lifecycle calls.
func Serve(ctx context.Context, listener net.Listener, credentials Credentials, backend Backend) error {
	defer listener.Close()
	auth, err := newAuthentication(credentials)
	if err != nil || backend == nil {
		return errProtocol
	}
	life, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(life, func() { _ = listener.Close() })
	var calls sync.WaitGroup
	defer func() {
		cancel()
		stop()
		calls.Wait()
	}()
	slots := make(chan struct{}, maxRequests)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if life.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			calls.Go(func() {
				defer func() { <-slots }()
				serveCall(life, conn, auth, backend)
			})
		default:
			_ = conn.Close()
		}
	}
}

func serveCall(ctx context.Context, conn net.Conn, auth authentication, backend Backend) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if conn.SetDeadline(time.Now().Add(authTimeout)) != nil || auth.authenticate(conn, false) != nil {
		return
	}
	var msg request
	if readFrame(conn, maxRequestBytes, &msg) != nil || !msg.valid() {
		return
	}
	cutoff := msg.Deadline
	if msg.Op != wait {
		cap := time.Now().Add(maxCallTime)
		if cutoff.IsZero() || cap.Before(cutoff) {
			cutoff = cap
		}
	}
	var cancel context.CancelFunc
	call := ctx
	if cutoff.IsZero() {
		call, cancel = context.WithCancel(call)
	} else {
		call, cancel = context.WithDeadline(call, cutoff)
	}
	defer cancel()
	if conn.SetDeadline(cutoff) != nil || call.Err() != nil {
		return
	}
	if msg.Op == open {
		serveOpen(ctx, call, cancel, conn, msg, backend)
		return
	}
	// Unary clients never send anything after their single request; a read can
	// observe client cancellation independently of the handler and response.
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		var b [1]byte
		_, _ = conn.Read(b[:])
		cancel()
	}()
	defer func() { _ = conn.Close(); <-peerDone }()
	reply, err := dispatch(call, msg, backend)
	if err != nil {
		reply = response{Error: wireError(err)}
	}
	if reply.valid(msg.Op) {
		_ = writeFrame(conn, maxRPCBytes, reply)
	}
}

func dispatch(ctx context.Context, msg request, b Backend) (response, error) {
	switch msg.Op {
	case manifest:
		m, err := b.Manifest(ctx, msg.Digest)
		return response{Manifest: m}, err
	case acquire:
		l, err := b.Acquire(ctx, *msg.Spec)
		return response{Lease: &l}, err
	case setEgress:
		return response{}, b.SetEgress(ctx, msg.Instance, msg.Policy)
	case wait:
		e, err := b.Wait(ctx, msg.Instance)
		return response{Exit: &e}, err
	case terminate:
		return response{}, b.Terminate(ctx, msg.Instance)
	case release:
		return response{}, b.Release(ctx, msg.Instance)
	case reconcile:
		return response{}, b.Reconcile(ctx)
	}
	return response{}, errProtocol
}

type observedOpen struct {
	net.Conn
	first     [1]byte
	ready     chan struct{}
	err       error
	readFirst bool
}

func (p *observedOpen) Read(b []byte) (int, error) {
	if len(b) == 0 || p.readFirst {
		return p.Conn.Read(b)
	}
	<-p.ready
	if p.err != nil {
		return 0, p.err
	}
	b[0] = p.first[0]
	p.readFirst = true
	return 1, nil
}

func serveOpen(life, call context.Context, cancel context.CancelFunc, conn net.Conn, msg request, backend Backend) {
	// Watch for abandonment during the guest startup without consuming any
	// bytes of a successful tunnel: replay the first byte to its single pump.
	peer := &observedOpen{Conn: conn, ready: make(chan struct{})}
	go func() {
		defer close(peer.ready)
		if _, err := io.ReadFull(conn, peer.first[:]); err != nil {
			peer.err = err
			cancel()
		}
	}()
	defer func() { _ = conn.Close(); <-peer.ready }()
	handshake, channel, err := backend.Open(call, msg.Instance, msg.Bootstrap)
	if channel != nil {
		defer channel.Close()
	}
	if err == nil {
		if channel == nil || len(handshake) > gvxipc.MaxControl {
			err = errProtocol
		} else {
			_, err = gvxipc.ValidateHandshake(handshake, GuestSocketDir)
		}
	}
	if err != nil {
		_ = writeFrame(conn, maxRPCBytes, response{Error: wireError(err)})
		return
	}
	if call.Err() != nil || writeFrame(conn, maxRPCBytes, response{Handshake: handshake}) != nil || conn.SetDeadline(time.Time{}) != nil {
		return
	}
	stop := context.AfterFunc(life, func() { _ = channel.Close() })
	defer stop()
	pump(peer, channel)
}

// Closing both sides makes the tunnel fail closed on any broken direction and
// joins its only other producer before the supervisor replies or shuts down.
func pump(a, b io.ReadWriteCloser) {
	done := make(chan struct{})
	var once sync.Once
	closeBoth := func() {
		once.Do(func() { _ = a.Close(); _ = b.Close() })
	}
	go func() {
		defer close(done)
		_, _ = io.Copy(a, b)
		closeBoth()
	}()
	_, _ = io.Copy(b, a)
	closeBoth()
	<-done
}

func knownError(code string) bool {
	switch code {
	case "HOST_PREREQUISITE_FAILED", "INVALID_CONFIGURATION", "CLEANUP_INCOMPLETE", "MODULE_ALREADY_ACTIVE",
		"HOST_RECONCILIATION_PENDING", "APPROVAL_MISMATCH", "BUDGET_EXCEEDED", "VOLUME_BUSY", "EGRESS_REVOKED",
		"UNSUPPORTED_TARGET", "ENGINE_CAPABILITY_MISSING", "NOT_FOUND", "CANCELLED", "DEADLINE_EXCEEDED", "SESSION_FAILED":
		return true
	}
	return false
}

func wireError(err error) string {
	var failure *host.Error
	switch {
	case errors.Is(err, host.ErrCleanupIncomplete):
		return "CLEANUP_INCOMPLETE"
	case errors.As(err, &failure) && failure.Reason == "CLEANUP_INCOMPLETE":
		return failure.Reason
	case errors.Is(err, context.DeadlineExceeded):
		return "DEADLINE_EXCEEDED"
	case errors.Is(err, context.Canceled):
		return "CANCELLED"
	case failure != nil && knownError(failure.Reason):
		return failure.Reason
	default:
		return "SESSION_FAILED"
	}
}

func remoteError(code string) error {
	switch code {
	case "DEADLINE_EXCEEDED":
		return context.DeadlineExceeded
	case "CANCELLED":
		return context.Canceled
	}
	if !knownError(code) {
		return errProtocol
	}
	failure := &host.Error{Reason: code, Message: "portable supervisor operation failed"}
	if code == "CLEANUP_INCOMPLETE" {
		return errors.Join(host.ErrCleanupIncomplete, failure)
	}
	return failure
}

type Client struct {
	endpoint, installation string
	auth                   authentication
}

func NewClient(endpoint string, credentials Credentials, installation string) (*Client, error) {
	auth, err := newAuthentication(credentials)
	if err != nil || installation == "" || !filepath.IsAbs(endpoint) || filepath.Clean(endpoint) != endpoint {
		return nil, errProtocol
	}
	return &Client{endpoint: endpoint, installation: installation, auth: auth}, nil
}

func (c *Client) call(ctx context.Context, msg request) (reply response, ch net.Conn, result error) {
	if !msg.valid() {
		return reply, nil, errProtocol
	}
	if ctx == nil {
		return reply, nil, errProtocol
	}
	msg.Deadline, _ = ctx.Deadline()
	if msg.Deadline.IsZero() && msg.Op != wait {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, maxCallTime)
		defer cancel()
		msg.Deadline, _ = ctx.Deadline()
	}
	dial, cancel := context.WithTimeout(ctx, authTimeout)
	conn, err := process.Dial(dial, c.endpoint)
	deadline, _ := dial.Deadline()
	cancel()
	if err != nil {
		return reply, nil, err
	}
	remote := false
	defer func() {
		if ch == nil {
			_ = conn.Close()
		}
		if result != nil && !remote && ctx.Err() != nil {
			result = ctx.Err()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err = conn.SetDeadline(deadline); err == nil {
		err = c.auth.authenticate(conn, true)
	}
	if err == nil {
		err = writeFrame(conn, maxRequestBytes, msg)
	}
	if err == nil {
		err = conn.SetDeadline(msg.Deadline)
	}
	if err == nil {
		err = readFrame(conn, maxRPCBytes, &reply)
	}
	if err != nil {
		return reply, nil, err
	}
	if !reply.valid(msg.Op) {
		return reply, nil, errProtocol
	}
	if reply.Error != "" {
		remote = true
		return reply, nil, remoteError(reply.Error)
	}
	if msg.Op == open {
		if !stop() {
			return reply, nil, ctx.Err()
		}
		if err = conn.SetDeadline(time.Time{}); err != nil {
			return reply, nil, err
		}
		return reply, conn, nil
	}
	return reply, nil, nil
}

func (c *Client) ImageManifest(ctx context.Context, digest string) ([]byte, error) {
	r, _, err := c.call(ctx, request{Op: manifest, Digest: digest})
	return r.Manifest, err
}

func sameLaunch(a, b host.LaunchSpec) bool {
	return a.ModuleID == b.ModuleID && a.InstanceID == b.InstanceID && a.ImageDigest == b.ImageDigest &&
		a.InitialEgress == b.InitialEgress && a.UID == b.UID && a.GID == b.GID && a.Resources == b.Resources &&
		a.ConfigRevision == b.ConfigRevision && a.ApprovalRevision == b.ApprovalRevision &&
		slices.Equal(a.Args, b.Args) && slices.Equal(a.Entrypoint, b.Entrypoint)
}

func (c *Client) Acquire(ctx context.Context, spec host.LaunchSpec) (host.Lease, error) {
	r, _, err := c.call(ctx, request{Op: acquire, Spec: &spec})
	if err != nil {
		return host.Lease{}, err
	}
	l := *r.Lease
	topology := host.NetworkNone
	if spec.InitialEgress == host.EgressPublicInternet {
		topology = host.NetworkPublicV4
	}
	if l.Ownership.RuntimeInstallationID != c.installation || l.Ownership.InstallationID != c.installation ||
		l.Ownership.EpochID != c.auth.epoch || l.Ownership.InstanceID != spec.InstanceID || !sameLaunch(l.Spec, spec) ||
		l.Topology != topology || l.SandboxUID != spec.UID || l.SandboxGID != spec.GID {
		return host.Lease{}, errProtocol
	}
	return l, nil
}

func (c *Client) Open(ctx context.Context, id string, bootstrap []string) ([]byte, io.ReadWriteCloser, error) {
	r, conn, err := c.call(ctx, request{Op: open, Instance: id, Bootstrap: bootstrap})
	if err != nil {
		return nil, nil, err
	}
	return r.Handshake, conn, nil
}

func (c *Client) SetEgress(ctx context.Context, id string, p host.EgressPolicy) error {
	_, _, err := c.call(ctx, request{Op: setEgress, Instance: id, Policy: p})
	return err
}

func (c *Client) Wait(ctx context.Context, id string) (host.ProcessExit, error) {
	r, _, err := c.call(ctx, request{Op: wait, Instance: id})
	if err != nil {
		return host.ProcessExit{}, err
	}
	return *r.Exit, nil
}

func (c *Client) Terminate(ctx context.Context, id string) error {
	_, _, err := c.call(ctx, request{Op: terminate, Instance: id})
	return err
}

func (c *Client) Release(ctx context.Context, id string) error {
	_, _, err := c.call(ctx, request{Op: release, Instance: id})
	return err
}

func (c *Client) Reconcile(ctx context.Context) error {
	_, _, err := c.call(ctx, request{Op: reconcile})
	return err
}
