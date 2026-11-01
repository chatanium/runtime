package runtime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"google.golang.org/grpc/credentials"
)

func primarySessionPair(t *testing.T) (*yamux.Session, *yamux.Session, net.Conn) {
	t.Helper()
	// TMPDIR may exceed AF_UNIX's address bound; keep this private fixture
	// directory short without weakening the production socket-path policy.
	directory, err := os.MkdirTemp("/tmp", "fm-mux-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	listener, err := net.Listen("unix", filepath.Join(directory, "mux.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	rawClient, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rawClient.Close() })
	rawServer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rawServer.Close() })
	config := yamux.DefaultConfig()
	config.EnableKeepAlive = false
	config.LogOutput = io.Discard
	server, err := yamux.Server(rawServer, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, err := yamux.Client(rawClient, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, server, rawClient
}

func primaryStreamPair(t *testing.T, client, server *yamux.Session) (net.Conn, net.Conn) {
	t.Helper()
	out, err := client.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })
	in, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close() })
	return out, in
}

func primaryCertificate(t *testing.T, serial int64) tls.Certificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private, Leaf: leaf}
}

func primaryTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	clientCert, serverCert := primaryCertificate(t, 1), primaryCertificate(t, 2)
	clientRoots, serverRoots := x509.NewCertPool(), x509.NewCertPool()
	clientRoots.AddCert(clientCert.Leaf)
	serverRoots.AddCert(serverCert.Leaf)
	return &tls.Config{
		Certificates: []tls.Certificate{clientCert}, RootCAs: serverRoots,
		ClientCAs: serverRoots, ClientAuth: tls.RequireAndVerifyClientCert,
		ServerName: "localhost", MinVersion: tls.VersionTLS12,
	}, &tls.Config{
		Certificates: []tls.Certificate{serverCert}, RootCAs: clientRoots,
		ClientCAs: clientRoots, ClientAuth: tls.RequireAndVerifyClientCert,
		ServerName: "localhost", MinVersion: tls.VersionTLS12,
	}
}

type primaryHandshakeResult struct {
	conn net.Conn
	auth credentials.AuthInfo
	err  error
}

func primaryServerHandshake(config *tls.Config, raw net.Conn) <-chan primaryHandshakeResult {
	result := make(chan primaryHandshakeResult, 1)
	go func() {
		conn, auth, err := credentials.NewTLS(config).ServerHandshake(raw)
		result <- primaryHandshakeResult{conn: conn, auth: auth, err: err}
	}()
	return result
}

func awaitPrimaryHandshake(t *testing.T, ctx context.Context, result <-chan primaryHandshakeResult) primaryHandshakeResult {
	t.Helper()
	select {
	case r := <-result:
		return r
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		return primaryHandshakeResult{}
	}
}

func assertPrimaryClosed(t *testing.T, ctx context.Context, owner *primaryTransport, session *yamux.Session, raw net.Conn) {
	t.Helper()
	if err := owner.close(ctx); err != nil {
		t.Fatal(err)
	}
	if !session.IsClosed() {
		t.Fatal("physical mux session remains open")
	}
	if err := raw.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("physical Unix connection remains open: %v", err)
	}
	if err := owner.close(ctx); err != nil {
		t.Fatalf("joining the same completed close: %v", err)
	}
}

func TestPrimaryTransportJoinsPhysicalSessionWithExactMutualTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, server, raw := primarySessionPair(t)
	out, in := primaryStreamPair(t, client, server)
	clientTLS, serverTLS := primaryTLSConfigs(t)
	owner := &primaryTransport{}
	creds := &primaryCredentials{TransportCredentials: credentials.NewTLS(clientTLS), owner: owner}
	serverDone := primaryServerHandshake(serverTLS, in)
	conn, auth, err := creds.Clone().ClientHandshake(ctx, "localhost", out)
	if err != nil {
		t.Fatal(err)
	}
	peer := awaitPrimaryHandshake(t, ctx, serverDone)
	if peer.err != nil {
		t.Fatal(peer.err)
	}
	if got := auth.(credentials.TLSInfo).State.PeerCertificates; len(got) != 1 || !bytes.Equal(got[0].Raw, serverTLS.Certificates[0].Leaf.Raw) {
		t.Fatal("primary peer identity changed")
	}
	if got := peer.auth.(credentials.TLSInfo).State.PeerCertificates; len(got) != 1 || !bytes.Equal(got[0].Raw, clientTLS.Certificates[0].Leaf.Raw) {
		t.Fatal("primary client identity changed")
	}
	_ = conn.Close()
	_ = peer.conn.Close()
	if client.IsClosed() {
		t.Fatal("closing the TLS/gRPC stream unexpectedly closed the physical mux")
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("fixture did not retain the physical Unix connection: %v", err)
	}
	assertPrimaryClosed(t, ctx, owner, client, raw)
}

func TestPrimaryTransportRetainsMutualTLSTrustRejection(t *testing.T) {
	for _, side := range []string{"server_identity", "client_identity"} {
		t.Run(side, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			client, server, raw := primarySessionPair(t)
			out, in := primaryStreamPair(t, client, server)
			clientTLS, serverTLS := primaryTLSConfigs(t)
			if side == "server_identity" {
				clientTLS.RootCAs = x509.NewCertPool()
			} else {
				serverTLS.ClientCAs = x509.NewCertPool()
			}
			owner := &primaryTransport{}
			creds := &primaryCredentials{TransportCredentials: credentials.NewTLS(clientTLS), owner: owner}
			serverDone := primaryServerHandshake(serverTLS, in)
			conn, _, err := creds.ClientHandshake(ctx, "localhost", out)
			peer := awaitPrimaryHandshake(t, ctx, serverDone)
			if peer.conn != nil {
				_ = peer.conn.Close()
			}
			if side == "server_identity" {
				var rejected *tls.CertificateVerificationError
				if !errors.As(err, &rejected) {
					t.Fatalf("untrusted primary server was not rejected by TLS: %v", err)
				}
			} else {
				var rejected *tls.CertificateVerificationError
				if !errors.As(peer.err, &rejected) {
					t.Fatalf("untrusted primary client was not rejected by TLS: %v", peer.err)
				}
				if err == nil {
					_ = conn.SetReadDeadline(time.Now().Add(time.Second))
					var one [1]byte
					if _, err := conn.Read(one[:]); err == nil {
						t.Fatal("rejected client retained a usable TLS stream")
					}
				}
			}
			if conn != nil {
				_ = conn.Close()
			}
			assertPrimaryClosed(t, ctx, owner, client, raw)
		})
	}
}

func TestPrimaryTransportOwnsCanceledHandshake(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	client, server, raw := primarySessionPair(t)
	out, _ := primaryStreamPair(t, client, server)
	clientTLS, _ := primaryTLSConfigs(t)
	owner := &primaryTransport{}
	creds := &primaryCredentials{TransportCredentials: credentials.NewTLS(clientTLS), owner: owner}
	if _, _, err := creds.ClientHandshake(ctx, "localhost", out); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled TLS handshake: %v", err)
	}
	cleanup, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	assertPrimaryClosed(t, cleanup, owner, client, raw)
}

func TestPrimaryTransportCloseJoinsInFlightTLSHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, server, raw := primarySessionPair(t)
	out, in := primaryStreamPair(t, client, server)
	clientTLS, _ := primaryTLSConfigs(t)
	owner := &primaryTransport{}
	creds := &primaryCredentials{TransportCredentials: credentials.NewTLS(clientTLS), owner: owner}
	result := make(chan error, 1)
	go func() {
		_, _, err := creds.ClientHandshake(ctx, "localhost", out)
		result <- err
	}()
	// Observe the real ClientHello without answering it: TLS is in flight.
	_ = in.SetReadDeadline(time.Now().Add(5 * time.Second))
	var first [1]byte
	if _, err := io.ReadFull(in, first[:]); err != nil {
		t.Fatal(err)
	}
	assertPrimaryClosed(t, ctx, owner, client, raw)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("incomplete TLS handshake unexpectedly authenticated")
		}
	case <-ctx.Done():
		t.Fatal("TLS handshake did not join physical close")
	}
}
