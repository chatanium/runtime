package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

const (
	protocolVersion = 2
	helloLimit      = 64 << 10
	minFrameBytes   = 16 << 10
	maxFrameBytes   = 4 << 20
	frameHello      = 0x01
	frameRequest    = 0x02
	frameResponse   = 0x03
	frameGoAway     = 0x0a
	flagEndStream   = 0x01
)

// RPCError is an authenticated rejection from GVX, distinct from a lost
// connection or protocol failure (where application may be indeterminate).
type RPCError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Errno     int    `json:"errno"`
	Retryable bool   `json:"retryable"`
}

func (e *RPCError) Error() string { return e.Code + ": " + e.Message }

type helloReply struct {
	OK           bool      `json:"ok"`
	Version      int       `json:"version"`
	SandboxID    string    `json:"sandbox_id"`
	MaxFrame     int       `json:"max_frame_bytes"`
	Capabilities []string  `json:"capabilities"`
	Features     []string  `json:"features"`
	Error        *RPCError `json:"error"`
}

type frame struct {
	kind, flags byte
	channel     uint16
	stream      uint32
	payload     []byte
}

func readFrame(r io.Reader, limit int) (frame, error) {
	var header [12]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return frame{}, err
	}
	n := binary.BigEndian.Uint32(header[8:])
	if n > uint32(limit) {
		return frame{}, fmt.Errorf("GVX frame exceeds %d bytes", limit)
	}
	f := frame{kind: header[0], flags: header[1], channel: binary.BigEndian.Uint16(header[2:]),
		stream: binary.BigEndian.Uint32(header[4:]), payload: make([]byte, int(n))}
	_, err := io.ReadFull(r, f.payload)
	return f, err
}

func writeFrame(w io.Writer, f frame, limit int) error {
	if len(f.payload) > limit {
		return fmt.Errorf("GVX frame exceeds %d bytes", limit)
	}
	var header [12]byte
	header[0], header[1] = f.kind, f.flags
	binary.BigEndian.PutUint16(header[2:], f.channel)
	binary.BigEndian.PutUint32(header[4:], f.stream)
	binary.BigEndian.PutUint32(header[8:], uint32(len(f.payload)))
	for _, part := range [][]byte{header[:], f.payload} {
		n, err := w.Write(part)
		if err != nil {
			return err
		}
		if n != len(part) {
			return io.ErrShortWrite
		}
	}
	return nil
}

func negotiate(ctx context.Context, conn *net.UnixConn, token string) (helloReply, error) {
	until, _ := ctx.Deadline() // Connect always applies a bounded context.
	if err := conn.SetDeadline(until); err != nil {
		return helloReply{}, err
	}
	cancelHandshake := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer cancelHandshake()
	payload, err := json.Marshal(struct {
		Version int    `json:"version"`
		Token   string `json:"token,omitempty"`
		Client  string `json:"client"`
	}{protocolVersion, token, "chatanium-portable-v2"})
	if err != nil {
		return helloReply{}, err
	}
	if _, err := io.WriteString(conn, "GVX2"); err != nil {
		return helloReply{}, err
	}
	if err := writeFrame(conn, frame{kind: frameHello, payload: payload}, helloLimit); err != nil {
		return helloReply{}, err
	}
	f, err := readFrame(conn, helloLimit)
	if err != nil {
		return helloReply{}, err
	}
	var hello helloReply
	if f.kind != frameHello || f.stream != 0 || f.channel != 0 || f.flags != 0 {
		return hello, errors.New("invalid gvx-ctrl/2 HELLO frame")
	}
	if err := json.Unmarshal(f.payload, &hello); err != nil {
		return hello, fmt.Errorf("decode GVX HELLO: %w", err)
	}
	if !hello.OK && hello.Error != nil && hello.Error.Code != "" {
		return hello, hello.Error
	}
	if !hello.OK || hello.Error != nil || hello.Version != protocolVersion || hello.MaxFrame < minFrameBytes || hello.MaxFrame > maxFrameBytes {
		return hello, errors.New("invalid gvx-ctrl/2 HELLO response")
	}
	if !cancelHandshake() {
		return hello, ctx.Err()
	}
	return hello, conn.SetDeadline(time.Time{})
}

type controlWire struct {
	conn      *net.UnixConn
	maxFrame  int
	next      uint32 // only accessed by the serialized RPC sender
	pending   atomic.Uint32
	responses chan frame
}

func (a *GVXAdapter) readControl() {
	for {
		f, err := readFrame(a.wire.conn, a.wire.maxFrame)
		if err != nil {
			if a.stopReply.Load() && errors.Is(err, io.EOF) {
				// A successful stop reply can be followed by EOF while GVX
				// still tears down its backing handles. Stop waits on Peer.
				return
			}
			if errors.Is(err, io.EOF) && a.peer.Completing != nil && a.peer.Completing() {
				a.drainPeer(fmt.Errorf("%w after verified bridge EXIT: %w", ErrPeerClosing, err))
				return
			}
			a.connectionLost(err)
			return
		}
		if f.kind == frameGoAway && f.stream == 0 && f.channel == 0 && f.flags == 0 {
			var reason RPCError
			if err := json.Unmarshal(f.payload, &reason); err != nil ||
				reason.Code != "SANDBOX_EXITING" || reason.Message != "sandbox exiting" {
				a.terminate(fmt.Errorf("%w: invalid GVX GOAWAY", ErrControlLost), true)
				return
			}
			if a.stopping.Load() {
				// GVX announces shutdown before draining the active stop RPC.
				// Until its reply arrives, EOF still forces the owned process.
				continue
			}
			// Stock rungv sends this only after Sandbox.Run returns. No
			// network grant remains usable; observe teardown, not just EOF.
			a.drainPeer(ErrPeerClosing)
			return
		}
		if f.kind != frameResponse || f.stream == 0 || f.channel != 0 || f.flags != flagEndStream || !a.wire.pending.CompareAndSwap(f.stream, 0) {
			a.terminate(fmt.Errorf("%w: unexpected frame type=%d stream=%d", ErrControlLost, f.kind, f.stream), true)
			return
		}
		if a.stopping.Load() {
			a.stopReply.Store(true)
		}
		select {
		case a.wire.responses <- f:
		case <-a.done:
			return
		}
	}
}

func (a *GVXAdapter) rpc(ctx context.Context, method string, params, result any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.wire.next == 0 {
		return errors.New("GVX RPC stream IDs exhausted")
	}
	if params == nil {
		params = struct{}{}
	}
	payload, err := json.Marshal(struct {
		Method string `json:"method"`
		Params any    `json:"params"`
	}{method, params})
	if err != nil {
		return err
	}
	stream := a.wire.next
	a.wire.next += 2
	deadline, _ := ctx.Deadline()
	if err := a.wire.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	a.wire.pending.Store(stream)
	if err := writeFrame(a.wire.conn, frame{kind: frameRequest, flags: flagEndStream, stream: stream, payload: payload}, a.wire.maxFrame); err != nil {
		return fmt.Errorf("%w: write %s: %w", ErrControlLost, method, err)
	}
	select {
	case f := <-a.wire.responses:
		var env struct {
			OK     *bool           `json:"ok"`
			Result json.RawMessage `json:"result"`
			Error  *RPCError       `json:"error"`
		}
		if err := json.Unmarshal(f.payload, &env); err != nil {
			return fmt.Errorf("%w: decode %s reply: %w", ErrControlLost, method, err)
		}
		if env.OK != nil && !*env.OK && len(env.Result) == 0 && env.Error != nil && env.Error.Code != "" {
			switch env.Error.Code {
			case "UNSUPPORTED", "FORBIDDEN_BY_POLICY", "LOCKDOWN_DENIED":
				return fmt.Errorf("%w: %s: %w", ErrCapabilityMissing, method, env.Error)
			}
			return fmt.Errorf("%s: %w", method, env.Error)
		}
		if env.OK == nil || !*env.OK || env.Error != nil || len(env.Result) == 0 || bytes.Equal(env.Result, []byte("null")) {
			return fmt.Errorf("%w: invalid %s response envelope", ErrControlLost, method)
		}
		if err := json.Unmarshal(env.Result, result); err != nil {
			return fmt.Errorf("%w: decode %s result: %w", ErrControlLost, method, err)
		}
		return nil
	case <-a.done:
		return a.Err()
	case <-ctx.Done():
		return fmt.Errorf("%w: %s outcome unknown: %w", ErrControlLost, method, ctx.Err())
	}
}
