package runtime

import (
	"context"
	"net"
	"sync"

	"github.com/hashicorp/yamux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
)

// primaryTransport owns the physical mux session, not merely its gRPC streams.
// go-plugin's GRPCClient.Close closes those streams but does not join the mux.
// This lock protects transport resources only; Instance.mu remains authoritative
// for lifecycle, admission and authority.
type primaryTransport struct {
	mu             sync.Mutex
	session        *yamux.Session
	closing        bool
	closeDone      chan struct{}
	closeError     error
	handshakes     int
	handshakesDone chan struct{}
}

// primaryCredentials delegates the actual AutoMTLS credentials populated by
// go-plugin.Start. It changes neither trust nor authentication behavior.
type primaryCredentials struct {
	credentials.TransportCredentials
	owner *primaryTransport
}

func (c *primaryCredentials) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	stream, ok := raw.(*yamux.Stream)
	if !ok {
		return nil, nil, runtimeError(codes.FailedPrecondition, "PROTOCOL_INCOMPATIBLE")
	}
	// Capture before TLS: rejected and canceled handshakes own a session too.
	if err := c.owner.beginHandshake(stream.Session()); err != nil {
		return nil, nil, err
	}
	defer c.owner.endHandshake()
	return c.TransportCredentials.ClientHandshake(ctx, authority, raw)
}

func (c *primaryCredentials) Clone() credentials.TransportCredentials {
	return &primaryCredentials{TransportCredentials: c.TransportCredentials.Clone(), owner: c.owner}
}

func (t *primaryTransport) beginHandshake(session *yamux.Session) error {
	t.mu.Lock()
	if t.session != nil && t.session != session {
		t.mu.Unlock()
		return runtimeError(codes.FailedPrecondition, "PROTOCOL_INCOMPATIBLE")
	}
	t.session = session
	if t.closing {
		done, start := t.startCloseLocked()
		t.mu.Unlock()
		if start {
			t.closeSession(session, done)
		}
		return context.Canceled
	}
	if t.handshakes == 0 {
		t.handshakesDone = make(chan struct{})
	}
	t.handshakes++
	t.mu.Unlock()
	return nil
}

func (t *primaryTransport) endHandshake() {
	t.mu.Lock()
	t.handshakes--
	if t.handshakes == 0 {
		close(t.handshakesDone)
	}
	t.mu.Unlock()
}

func (t *primaryTransport) startCloseLocked() (chan struct{}, bool) {
	if t.session == nil || t.closeDone != nil {
		return t.closeDone, false
	}
	t.closeDone = make(chan struct{})
	return t.closeDone, true
}

func (t *primaryTransport) closeSession(session *yamux.Session, done chan struct{}) {
	// Session.Close has no context parameter and joins its send/receive workers.
	// Retain this single worker and its result if the cleanup deadline expires;
	// subsequent cleanup joins the same work rather than spawning a retry.
	go func() {
		err := session.Close()
		t.mu.Lock()
		t.closeError = err
		close(done)
		t.mu.Unlock()
	}()
}

func (t *primaryTransport) close(ctx context.Context) error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	t.closing = true
	session := t.session
	done, start := t.startCloseLocked()
	handshakesDone := t.handshakesDone
	t.mu.Unlock()
	if start {
		t.closeSession(session, done)
	}
	for _, pending := range []<-chan struct{}{done, handshakesDone} {
		if pending == nil {
			continue
		}
		select {
		case <-pending:
			continue
		default:
		}
		select {
		case <-pending:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	t.mu.Lock()
	err := t.closeError
	t.mu.Unlock()
	return err
}
