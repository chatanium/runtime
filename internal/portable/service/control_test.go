//go:build linux || darwin || windows

package service

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thirdscam/chatanium/internal/portable/ipcpath"
	"github.com/thirdscam/chatanium/internal/portable/process"
)

const testControlEpoch = "active-epoch"

func newTestControl(t *testing.T, fence func(context.Context) error, handler ControlHandler) (string, *controlServer, func(bool)) {
	t.Helper()
	base, err := ipcpath.FallbackBase()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(base, "ctl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(root) })
	leaf, err := ipcpath.Directory(root, testControlEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(leaf) })
	if err = process.ProtectPrivateDir(leaf); err != nil {
		t.Fatal(err)
	}
	s, err := listenControl(filepath.Join(leaf, controlLeaf), testControlEpoch, fence, handler)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	shutdown := func(clean bool) {
		once.Do(func() {
			s.drain()
			_ = s.listener.Close()
			s.close(clean)
		})
	}
	t.Cleanup(func() { shutdown(false) })
	return root, s, shutdown
}

func TestControlSocket(t *testing.T) {
	var fenced atomic.Bool
	watching := make(chan struct{})
	root, s, shutdown := newTestControl(t, func(context.Context) error {
		if !fenced.Load() {
			return errors.New("fence failed")
		}
		return nil
	}, func(ctx context.Context, op string, payload json.RawMessage) (json.RawMessage, error) {
		switch op {
		case "echo":
			return payload, nil
		case "watch":
			close(watching)
			<-ctx.Done()
			return nil, ctx.Err()
		default:
			return nil, errors.New("unknown operation")
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	request := func(op string, payload json.RawMessage) (json.RawMessage, error) {
		return exchangeControl(ctx, root, controlRequest{Version: controlVersion, Epoch: testControlEpoch, Op: op, Payload: payload})
	}
	assertCode := func(err error, code string) {
		t.Helper()
		var failure *controlFailure
		if !errors.As(err, &failure) || failure.Code != code {
			t.Fatalf("expected %s, got %v", code, err)
		}
	}
	assertStatus := func(want string) {
		t.Helper()
		status, err := request("status", nil)
		if err != nil || string(status) != want {
			t.Fatalf("status = %s, %v; want %s", status, err, want)
		}
	}
	assertStatus(`{"ready":false}`)
	_, err := request("echo", json.RawMessage(`{"test":1}`))
	assertCode(err, "NOT_READY")

	s.markReady()
	leaf, err := ipcpath.Directory(root, testControlEpoch)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(leaf, controlLeaf)
	stalled, err := process.Dial(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	if _, err = stalled.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	quickCtx, stopQuick := context.WithTimeout(ctx, controlReadTimeout/2)
	status, err := exchangeControl(quickCtx, root, controlRequest{Version: controlVersion, Epoch: testControlEpoch, Op: "status"})
	stopQuick()
	if err != nil || string(status) != `{"ready":true}` {
		t.Fatalf("status while a partial frame is stalled: %s, %v", status, err)
	}
	payload, err := request("echo", json.RawMessage(`{"test":1}`))
	if err != nil || string(payload) != `{"test":1}` {
		t.Fatalf("echo = %s, %v", payload, err)
	}
	if err = stalled.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = request("stop", nil)
	assertCode(err, "STOP_REJECTED")
	select {
	case <-s.request:
		t.Fatal("stop reached the worker after a failed fence")
	default:
	}

	watchResult := make(chan error, 1)
	go func() { _, err := request("watch", nil); watchResult <- err }()
	select {
	case <-watching:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	fenced.Store(true)
	stopResult := make(chan error, 1)
	go func() { _, err := request("stop", nil); stopResult <- err }()
	select {
	case <-s.request:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	assertCode(<-watchResult, "OPERATION_FAILED")
	s.markReady() // A late READY cannot reopen admissions.
	assertStatus(`{"ready":false}`)
	shutdown(true)
	if err = <-stopResult; err != nil {
		t.Fatalf("stop proof: %v", err)
	}
}

func TestControlRejectsInvalidStop(t *testing.T) {
	var fences atomic.Int32
	root, s, _ := newTestControl(t, func(context.Context) error {
		fences.Add(1)
		return nil
	}, nil)
	s.markReady()
	leaf, err := ipcpath.Directory(root, testControlEpoch)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(leaf, controlLeaf)
	for _, tt := range []struct {
		name string
		raw  string
		code string
	}{
		{"duplicate operation", `{"version":1,"epoch":"active-epoch","op":"status","op":"stop"}`, "BAD_REQUEST"},
		{"wrong version", `{"version":2,"epoch":"active-epoch","op":"stop"}`, "BAD_REQUEST"},
		{"stale epoch", `{"version":1,"epoch":"old-epoch","op":"stop"}`, "STALE_EPOCH"},
		{"stop payload", `{"version":1,"epoch":"active-epoch","op":"stop","payload":null}`, "BAD_REQUEST"},
		{"oversize", "", "BAD_REQUEST"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			conn, err := process.Dial(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			deadline, _ := ctx.Deadline()
			if err = conn.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if tt.raw == "" {
				var header [4]byte
				binary.BigEndian.PutUint32(header[:], controlMaxFrame+1)
				_, err = conn.Write(header[:])
			} else {
				err = writeControlFrame(conn, json.RawMessage(tt.raw))
			}
			if err != nil {
				t.Fatal(err)
			}
			var reply controlReply
			if err = readControlFrame(conn, &reply); err != nil {
				t.Fatal(err)
			}
			if reply.Version != controlVersion || reply.Epoch != testControlEpoch || reply.OK || reply.Error == nil || reply.Error.Code != tt.code {
				t.Fatalf("unexpected reply: %+v, error = %v", reply, reply.Error)
			}
		})
	}
	if n := fences.Load(); n != 0 {
		t.Fatalf("invalid requests invoked the stop fence %d times", n)
	}
}

func TestControlStopRequiresCleanupProof(t *testing.T) {
	root, s, shutdown := newTestControl(t, func(context.Context) error { return nil }, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := exchangeControl(ctx, root, controlRequest{Version: controlVersion, Epoch: testControlEpoch, Op: "stop"})
		result <- err
	}()
	select {
	case <-s.request:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	shutdown(false)
	var failure *controlFailure
	if err := <-result; !errors.As(err, &failure) || failure.Code != "CLEANUP_PENDING" {
		t.Fatalf("missing exit proof was not reported: %v", err)
	}
}
