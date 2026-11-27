// Package gvxipc implements the private, bounded stdio bridge protocol.
package gvxipc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
)

const (
	Init        byte = 1
	Handshake   byte = 2
	Open        byte = 3
	OpenOK      byte = 4
	Data        byte = 5
	Fin         byte = 6
	Exit        byte = 7
	Error       byte = 8
	RootsReady  byte = 9
	RootsCommit byte = 10
	MaxControl       = 60 * 1024
	MaxData          = 16 * 1024
	LogSlab          = 4096
)

type Side uint8

const (
	Host Side = iota
	Guest
)

type Limits struct{ ControlMessageMaxBytes, LogBufferBytes int64 }

func (l Limits) Control() int {
	if l.ControlMessageMaxBytes > MaxControl {
		return MaxControl
	}
	return int(l.ControlMessageMaxBytes)
}

// Workspace accounts for strict JSON/DER decoding, both DATA slabs, the caller's
// control encoding, the handshake scanner and the bounded diagnostic slab.
func Workspace(l Limits) error {
	c := l.Control()
	if c <= 0 || l.LogBufferBytes < int64(8*c+2*MaxData+65536+2*LogSlab) {
		return errors.New("bridge buffers exceed approved log buffer budget")
	}
	return nil
}

type state struct {
	init, roots, commit, handshake, open, opened bool
	fin                                          [2]bool
	terminal                                     [2]bool
	exited, failed                               bool
}

func (s *state) advance(from Side, typ byte, n int, max int) error {
	if from != Host && from != Guest || n < 0 || s.failed || s.terminal[from] {
		return errors.New("frame after terminal or invalid direction")
	}
	empty := typ == Open || typ == OpenOK || typ == Fin || typ == RootsCommit
	if empty && n != 0 || typ == Data && n > MaxData || !empty && typ != Data && (n == 0 || n > max) {
		return errors.New("invalid frame length")
	}
	switch typ {
	case Init:
		if from != Host || s.init {
			return errors.New("unexpected INIT")
		}
		s.init = true
	case RootsReady:
		if from != Guest || !s.init || s.roots {
			return errors.New("unexpected ROOTS_READY")
		}
		s.roots = true
	case RootsCommit:
		if from != Host || !s.roots || s.commit {
			return errors.New("unexpected ROOTS_COMMIT")
		}
		s.commit = true
	case Handshake:
		if from != Guest || !s.commit || s.handshake {
			return errors.New("unexpected HANDSHAKE")
		}
		s.handshake = true
	case Open:
		if from != Host || !s.handshake || s.open || s.exited {
			return errors.New("unexpected OPEN")
		}
		s.open = true
	case OpenOK:
		if from != Guest || !s.open || s.opened {
			return errors.New("unexpected OPEN_OK")
		}
		s.opened = true
	case Data:
		if !s.opened || s.fin[from] || s.exited {
			return errors.New("unexpected DATA")
		}
	case Fin:
		if !s.opened || s.fin[from] || s.exited {
			return errors.New("unexpected FIN")
		}
		s.fin[from] = true
	case Exit:
		if from != Guest || !s.commit || s.exited {
			return errors.New("unexpected EXIT")
		}
		s.exited = true
		s.terminal[Guest] = true
	case Error:
		s.failed = true
		s.terminal[from] = true
	default:
		return errors.New("unknown frame type")
	}
	return nil
}

var ErrInvalidFrame = errors.New("invalid bridge frame")

// Codec owns one reader and serializes writers. Read's payload is valid until
// the next Read. Headers are checked against shared direction/state/size bounds
// before a payload is read; no wire length is ever used as an allocation size.
type Codec struct {
	r           io.Reader
	w           io.Writer
	side        Side
	max         int
	mu, writeMu sync.Mutex
	state       state
	slab        []byte
}

func NewCodec(r io.Reader, w io.Writer, side Side, l Limits) (*Codec, error) {
	if err := Workspace(l); err != nil {
		return nil, err
	}
	n := l.Control()
	if n < MaxData {
		n = MaxData
	}
	return &Codec{r: r, w: w, side: side, max: l.Control(), slab: make([]byte, n)}, nil
}
func writeFull(w io.Writer, p []byte) error {
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
func (c *Codec) SendMagic() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writeFull(c.w, []byte(gvxcontract.BridgeMagic))
}
func (c *Codec) ReadMagic() error {
	var b [9]byte
	if _, e := io.ReadFull(c.r, b[:]); e != nil {
		return e
	}
	if string(b[:]) != gvxcontract.BridgeMagic {
		return errors.New("invalid bridge magic")
	}
	return nil
}
func (c *Codec) Write(typ byte, p []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	e := c.state.advance(c.side, typ, len(p), c.max)
	c.mu.Unlock()
	if e != nil {
		return e
	}
	var h [8]byte
	h[0] = typ
	binary.BigEndian.PutUint32(h[4:], uint32(len(p)))
	if e = writeFull(c.w, h[:]); e != nil {
		return e
	}
	return writeFull(c.w, p)
}
func (c *Codec) Read() (byte, []byte, error) {
	var h [8]byte
	_, e := io.ReadFull(c.r, h[:])
	if e != nil {
		c.mu.Lock()
		done := c.state.exited && !c.state.failed
		c.mu.Unlock()
		if e == io.EOF && done {
			return 0, nil, io.EOF
		}
		return 0, nil, fmt.Errorf("premature or truncated bridge stream: %w", e)
	}
	if h[1] != 0 || h[2] != 0 || h[3] != 0 {
		return 0, nil, fmt.Errorf("%w: nonzero reserved bytes", ErrInvalidFrame)
	}
	n64 := uint64(binary.BigEndian.Uint32(h[4:]))
	if n64 > uint64(len(c.slab)) {
		return 0, nil, fmt.Errorf("%w: exceeds fixed buffer", ErrInvalidFrame)
	}
	n := int(n64)
	c.mu.Lock()
	e = c.state.advance(1-c.side, h[0], n, c.max)
	c.mu.Unlock()
	if e != nil {
		return 0, nil, fmt.Errorf("%w: %v", ErrInvalidFrame, e)
	}
	if _, e = io.ReadFull(c.r, c.slab[:n]); e != nil {
		return 0, nil, fmt.Errorf("truncated frame payload: %w", e)
	}
	return h[0], c.slab[:n], nil
}
func (c *Codec) Exited() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.state.exited }

type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e ErrorPayload) Validate() error {
	switch e.Code {
	case "INVALID_INIT", "INVALID_HANDSHAKE", "INVALID_FRAME", "OPEN_FAILED", "STARTUP_TIMEOUT", "IO_FAILED", "CHILD_FAILED":
	default:
		return errors.New("unknown bridge error code")
	}
	if len(e.Message) > 1024 {
		return errors.New("bridge error message exceeds bounds")
	}
	for _, v := range e.Message {
		if v == 0 {
			return errors.New("NUL in error")
		}
	}
	return nil
}

type ExitPayload struct {
	Kind  string `json:"kind"`
	Value uint32 `json:"value"`
}

func (e ExitPayload) Validate() error {
	if e.Kind == "exit" && e.Value <= 255 || e.Kind == "signal" && e.Value >= 1 && e.Value <= 64 {
		return nil
	}
	return errors.New("invalid child exit")
}

func DecodeExit(raw []byte, max int) (ExitPayload, error) {
	var wire struct {
		Kind  string  `json:"kind"`
		Value *uint32 `json:"value"`
	}
	if err := gvxcontract.DecodeStrict(raw, max, 4, &wire); err != nil || wire.Value == nil {
		return ExitPayload{}, fmt.Errorf("%w: invalid EXIT payload", ErrInvalidFrame)
	}
	result := ExitPayload{Kind: wire.Kind, Value: *wire.Value}
	if err := result.Validate(); err != nil {
		return ExitPayload{}, fmt.Errorf("%w: invalid EXIT result", ErrInvalidFrame)
	}
	return result, nil
}

func DecodeError(raw []byte, max int) (ErrorPayload, error) {
	var wire struct {
		Code    string  `json:"code"`
		Message *string `json:"message"`
	}
	if err := gvxcontract.DecodeStrict(raw, max, 4, &wire); err != nil || wire.Message == nil {
		return ErrorPayload{}, fmt.Errorf("%w: invalid ERROR payload", ErrInvalidFrame)
	}
	result := ErrorPayload{Code: wire.Code, Message: *wire.Message}
	if err := result.Validate(); err != nil {
		return ErrorPayload{}, fmt.Errorf("%w: invalid ERROR result", ErrInvalidFrame)
	}
	return result, nil
}
