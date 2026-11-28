//go:build linux

package host

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	sharedhost "github.com/thirdscam/chatanium/internal/host"
	"golang.org/x/sys/unix"
)

func TestGvxTransportTwoPhaseClose(t *testing.T) {
	dir, e := os.MkdirTemp("", "gvx-close-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "s")
	ln, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	ln.SetUnlinkOnClose(false)
	defer ln.Close()
	listener, e := ln.File()
	if e != nil {
		t.Fatal(e)
	}
	fd, e := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	endpoint := os.NewFile(uintptr(fd), "endpoint-pin")
	pipe := func() (*os.File, *os.File) {
		t.Helper()
		r, w, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { r.Close(); w.Close() })
		return r, w
	}
	stdinR, stdinW := pipe()
	stdoutR, stdoutW := pipe()
	stderrR, stderrW := pipe()
	hsR, hsW := pipe()
	diagR, diagW := pipe()
	defer stdinR.Close()
	defer stdoutW.Close()
	defer stderrW.Close()
	pidfd, e := unix.PidfdOpen(os.Getpid(), 0)
	if e != nil {
		t.Fatal(e)
	}
	stage := &StageProcess{Stdin: stdinW, Stdout: stdoutR, Stderr: stderrR, Listener: listener, Endpoint: endpoint}
	if e = prepareStagePipes(stage); e != nil {
		t.Fatal(e)
	}
	r := &gvxRunner{client: &Client{config: ClientConfig{OperationTimeout: 100 * time.Millisecond}}, stage: stage, listener: ln, handshakeReader: hsR, handshakeWriter: hsW, diagnosticReader: diagR, diagnosticWriter: diagW, pidfd: os.NewFile(uintptr(pidfd), "self-pidfd"), started: true, startDone: make(chan struct{}), done: make(chan struct{})}
	f := &RunnerFactory{runner: r}
	raw, e := hsW.SyscallConn()
	if e != nil {
		t.Fatal(e)
	}
	var sizeErr error
	if e = raw.Control(func(fd uintptr) { _, sizeErr = unix.FcntlInt(fd, unix.F_SETPIPE_SZ, 4096) }); e != nil || sizeErr != nil {
		t.Fatal(errors.Join(e, sizeErr))
	}
	if _, e = hsW.Write(make([]byte, 4096)); e != nil {
		t.Fatal(e)
	}
	readDone := make(chan struct{})
	go func() { var b [1]byte; _, _ = stage.Stdout.Read(b[:]); close(readDone) }()
	writeDone := make(chan struct{})
	go func() { _, _ = hsW.Write([]byte{1}); close(writeDone) }()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	before := time.Now()
	if e = f.BeginCloseTransport(canceled); e != nil {
		t.Fatal(e)
	}
	if time.Since(before) > time.Second {
		t.Fatal("phase one waited for joins")
	}
	for _, done := range []<-chan struct{}{readDone, writeDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("phase one failed to unblock physical I/O")
		}
	}
	var st unix.Stat_t
	if e = unix.Fstat(int(endpoint.Fd()), &st); e != nil {
		t.Fatalf("phase one released path pin: %v", e)
	}
	if e = unix.Fstat(int(listener.Fd()), &st); e != nil {
		t.Fatalf("phase one released listener pin: %v", e)
	}
	r.mu.Lock()
	fresh := r.cleanup.Err()
	r.mu.Unlock()
	if fresh != nil {
		t.Fatal("canceled startup context poisoned cleanup budget")
	}
	if e = f.CloseTransport(); !errors.Is(e, sharedhost.ErrCleanupIncomplete) {
		t.Fatalf("uncertain join returned success: %v", e)
	}
	if e = unix.Fstat(int(endpoint.Fd()), &st); e != nil {
		t.Fatal("uncertain join released endpoint")
	}
	// Resolve both actual joins; a subsequent final close can now prove absence.
	close(r.startDone)
	close(r.done)
	if e = f.CloseTransport(); e != nil {
		t.Fatal(e)
	}
	if _, e = endpoint.Stat(); !errors.Is(e, os.ErrClosed) {
		t.Fatalf("final endpoint pin not closed: %v", e)
	}
	if _, e = listener.Stat(); !errors.Is(e, os.ErrClosed) {
		t.Fatalf("final listener pin not closed: %v", e)
	}
	if _, e = hsR.Read(make([]byte, 1)); !errors.Is(e, os.ErrClosed) && e != io.EOF {
		t.Fatalf("synthetic reader not closed: %v", e)
	}
	if e = f.BeginCloseTransport(context.Background()); e != nil {
		t.Fatal(e)
	}
}
