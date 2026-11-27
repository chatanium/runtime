package service

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/portable/install"
	"github.com/thirdscam/chatanium/internal/portable/ipcpath"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/store"
	modruntime "github.com/thirdscam/chatanium/internal/runtime"
)

const (
	// Crash recovery recognizes this existing leaf in the private epoch directory.
	controlLeaf = "stop"

	controlVersion        = 1
	controlMaxFrame       = 1 << 20
	controlConnections    = 8
	controlReadTimeout    = 2 * time.Second
	controlWriteTimeout   = time.Second
	controlFenceTimeout   = 10 * time.Second
	controlRequestTimeout = 30 * time.Second
)

const (
	controlStarting uint32 = iota
	controlReady
	controlDraining
)

var errControlFrame = errors.New("invalid control frame")

type controlRequest struct {
	Version int             `json:"version"`
	Epoch   string          `json:"epoch"`
	Op      string          `json:"op"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type controlReply struct {
	Version int             `json:"version"`
	Epoch   string          `json:"epoch"`
	OK      bool            `json:"ok"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   *controlFailure `json:"error,omitempty"`
}

type controlFailure struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *controlFailure) Error() string { return e.Code + ": " + e.Message }

// ControlHandler handles service-specific operations only while the worker is
// ready. Calls can overlap. Handlers must honor ctx cancellation and return
// operator-safe errors.
type ControlHandler func(ctx context.Context, op string, payload json.RawMessage) (json.RawMessage, error)

type controlServer struct {
	listener net.Listener
	request  chan struct{}
	finish   chan struct{}
	once     sync.Once
	workers  sync.WaitGroup
	active   context.Context
	cancel   context.CancelFunc
	phase    atomic.Uint32
	clean    bool // Published by closing finish.
}

func listenControl(path, epoch string, fence func(context.Context) error, handler ControlHandler) (*controlServer, error) {
	ln, err := process.Listen(path)
	if err != nil {
		return nil, err
	}
	active, cancel := context.WithCancel(context.Background())
	s := &controlServer{
		listener: ln, request: make(chan struct{}), finish: make(chan struct{}),
		active: active, cancel: cancel,
	}
	slots := make(chan struct{}, controlConnections)
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		for {
			select {
			case slots <- struct{}{}:
			case <-s.finish:
				return
			}
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.workers.Add(1)
			go func() {
				defer s.workers.Done()
				defer func() { <-slots }()
				defer conn.Close()
				s.serve(conn, epoch, fence, handler)
			}()
		}
	}()
	return s, nil
}

func (s *controlServer) markReady() { s.phase.CompareAndSwap(controlStarting, controlReady) }

func (s *controlServer) drain() {
	s.phase.Store(controlDraining)
	s.cancel()
}

func (s *controlServer) close(clean bool) {
	s.clean = clean
	close(s.finish)
	s.workers.Wait()
}

func (s *controlServer) serve(conn net.Conn, epoch string, fence func(context.Context) error, handler ControlHandler) {
	if err := conn.SetReadDeadline(time.Now().Add(controlReadTimeout)); err != nil {
		return
	}
	var request controlRequest
	reply := controlReply{Version: controlVersion, Epoch: epoch}
	if err := readControlFrame(conn, &request); err != nil {
		reply.Error = &controlFailure{"BAD_REQUEST", "invalid control frame"}
	} else {
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return
		}
		reply.Payload, reply.Error = s.dispatch(request, epoch, fence, handler)
	}
	reply.OK = reply.Error == nil
	if err := conn.SetWriteDeadline(time.Now().Add(controlWriteTimeout)); err != nil {
		return
	}
	if err := writeControlFrame(conn, reply); errors.Is(err, errControlFrame) {
		reply.OK = false
		reply.Payload = nil
		reply.Error = &controlFailure{"BAD_RESPONSE", "operation result is not a bounded control message"}
		_ = writeControlFrame(conn, reply)
	}
}

func (s *controlServer) dispatch(r controlRequest, epoch string, fence func(context.Context) error, handler ControlHandler) (json.RawMessage, *controlFailure) {
	if r.Version != controlVersion || !validControlOp(r.Op) {
		return nil, &controlFailure{"BAD_REQUEST", "unsupported protocol version or invalid operation"}
	}
	if r.Epoch != epoch {
		return nil, &controlFailure{"STALE_EPOCH", "request does not address this foreground owner"}
	}
	switch r.Op {
	case "status", "stop":
		if len(r.Payload) != 0 {
			return nil, &controlFailure{"BAD_REQUEST", "operation does not accept a payload"}
		}
		if r.Op == "status" {
			if s.phase.Load() == controlReady {
				return json.RawMessage(`{"ready":true}`), nil
			}
			return json.RawMessage(`{"ready":false}`), nil
		}
		select {
		case <-s.request:
		default:
			ctx, cancel := context.WithTimeout(context.Background(), controlFenceTimeout)
			err := fence(ctx)
			cancel()
			if err != nil {
				return nil, &controlFailure{"STOP_REJECTED", err.Error()}
			}
			s.drain()
			s.once.Do(func() { close(s.request) })
		}
		<-s.finish
		if !s.clean {
			return nil, &controlFailure{"CLEANUP_PENDING", "foreground owner could not confirm cleanup"}
		}
		return nil, nil
	default:
		if handler == nil {
			return nil, &controlFailure{"UNKNOWN_OPERATION", "operation is not available"}
		}
		if s.phase.Load() != controlReady {
			return nil, &controlFailure{"NOT_READY", "foreground owner is not ready"}
		}
		ctx, cancel := context.WithTimeout(s.active, controlRequestTimeout)
		defer cancel()
		if err := ctx.Err(); err != nil {
			return nil, &controlFailure{"NOT_READY", "foreground owner is not ready"}
		}
		value, err := handler(ctx, r.Op, r.Payload)
		if err != nil {
			message := err.Error()
			if message == "" || len(message) > 4096 {
				message = "operation failed"
			}
			return nil, &controlFailure{"OPERATION_FAILED", message}
		}
		if len(value) > controlMaxFrame {
			return nil, &controlFailure{"BAD_RESPONSE", "operation result is not a bounded control message"}
		}
		return value, nil
	}
}

func validControlOp(op string) bool {
	if len(op) == 0 || len(op) > 64 {
		return false
	}
	for i := range len(op) {
		c := op[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func readControlFrame(r io.Reader, dst any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > controlMaxFrame {
		return errControlFrame
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return err
	}
	if err := gvxcontract.DecodeStrict(raw, controlMaxFrame, 32, dst); err != nil {
		return errControlFrame
	}
	return nil
}

func writeControlFrame(w io.Writer, value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > controlMaxFrame {
		return errControlFrame
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	if n, err := w.Write(header[:]); err != nil {
		return err
	} else if n != len(header) {
		return io.ErrShortWrite
	}
	if n, err := w.Write(raw); err != nil {
		return err
	} else if n != len(raw) {
		return io.ErrShortWrite
	}
	return nil
}

// Control sends one operation to the current foreground owner. Stop uses its
// own entry point because it must first fence admissions durably.
func Control(ctx context.Context, dir, op string, payload json.RawMessage) (json.RawMessage, error) {
	if op == "stop" || !validControlOp(op) || len(payload) > controlMaxFrame {
		return nil, errors.New("invalid control operation or payload")
	}
	ctx, cancel := context.WithTimeout(ctx, controlRequestTimeout)
	defer cancel()
	i, err := install.Open(dir)
	if err != nil {
		return nil, err
	}
	defer i.Close()
	db, err := i.Store(ctx)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	record, err := db.Installation(ctx)
	if err != nil {
		return nil, err
	}
	if record.EpochID == "" {
		return nil, errors.New("no foreground owner")
	}
	value, err := exchangeControl(ctx, i.Path, controlRequest{Version: controlVersion, Epoch: record.EpochID, Op: op, Payload: payload})
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return value, err
}

func exchangeControl(ctx context.Context, dir string, request controlRequest) (json.RawMessage, error) {
	leaf, err := ipcpath.Directory(dir, request.Epoch)
	if err != nil {
		return nil, err
	}
	conn, err := process.Dial(ctx, filepath.Join(leaf, controlLeaf))
	if err != nil {
		return nil, fmt.Errorf("contact foreground owner: %w", err)
	}
	defer conn.Close()
	cancelIO := context.AfterFunc(ctx, func() { conn.Close() })
	defer cancelIO()
	if deadline, ok := ctx.Deadline(); ok {
		if err = conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	if err = writeControlFrame(conn, request); err != nil {
		return nil, fmt.Errorf("send foreground owner request: %w", err)
	}
	var reply controlReply
	if err = readControlFrame(conn, &reply); err != nil {
		return nil, fmt.Errorf("await foreground owner: %w", err)
	}
	if reply.Version != controlVersion || reply.Epoch != request.Epoch || reply.OK != (reply.Error == nil) {
		return nil, errControlFrame
	}
	if reply.Error != nil {
		if len(reply.Payload) != 0 || reply.Error.Code == "" || reply.Error.Message == "" {
			return nil, errControlFrame
		}
		return nil, reply.Error
	}
	return reply.Payload, nil
}

// Stop fences admissions in SQLite before contacting the owner. A missing
// socket is not proof that a cleanup-pending child has gone away.
func Stop(ctx context.Context, dir string) error {
	i, err := install.Open(dir)
	if err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		cfg, err := modruntime.DecodeConfig(i.Manifest.Config)
		if err != nil {
			i.Close()
			return err
		}
		// A stuck local owner is not a reason to hang an operator forever.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(cfg.Defaults.DrainDeadline)+3*(time.Duration(cfg.Limits.TerminationDeadline)+time.Duration(cfg.Limits.HostOperationDeadline)))
		defer cancel()
	}
	defer i.Close()
	db, err := i.Store(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	record, err := db.Installation(ctx)
	if err != nil {
		return err
	}
	if record.Desired != store.DesiredStopped {
		if err = db.RequestStop(ctx, record.EpochID); err != nil {
			return err
		}
	}
	idle := func() error {
		current, err := db.Installation(ctx)
		if err != nil {
			return err
		}
		if current.WorkerPending || current.EpochID != "" && (current.Desired != store.DesiredStopped || current.EpochID != record.EpochID) {
			return errors.New("CLEANUP_PENDING: foreground owner has not confirmed exit")
		}
		runs, err := db.Runs(ctx)
		if err != nil {
			return err
		}
		if len(runs) != 0 {
			return errors.New("CLEANUP_PENDING: outstanding sandbox resources")
		}
		return nil
	}
	if record.EpochID == "" || record.Desired == store.DesiredStopped && !record.WorkerPending {
		return idle()
	}
	payload, err := exchangeControl(ctx, i.Path, controlRequest{Version: controlVersion, Epoch: record.EpochID, Op: "stop"})
	if err == nil {
		if len(payload) != 0 {
			return errors.New("CLEANUP_PENDING: invalid foreground stop proof")
		}
		return nil
	}
	var failure *controlFailure
	if errors.As(err, &failure) && failure.Code == "CLEANUP_PENDING" {
		return err
	}
	if idle() == nil {
		return nil
	}
	return fmt.Errorf("CLEANUP_PENDING: %w", err)
}
