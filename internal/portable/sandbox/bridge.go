package sandbox

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/gvxipc"
	"github.com/thirdscam/chatanium/internal/host"
)

const guestSocketDir = "/tmp/plugin-dir-portable"

func bridgeInit(module Module, bootstrap []string, roots gvxcontract.RootInitManifest, controlLimit int) (gvxcontract.BridgeInit, error) {
	s, image := module.Spec, module.Image
	// Configure resolves image defaults before review. In particular a
	// CMD-only image has its entire command in Entrypoint and empty Args.
	if len(s.Entrypoint)+len(s.Args) > controlLimit/32 || len(image.ImageEnv)+len(bootstrap) > controlLimit/32 {
		return gvxcontract.BridgeInit{}, errors.New("bridge launch vectors exceed approved workspace")
	}
	argv := make([]string, 0, len(s.Entrypoint)+len(s.Args))
	argv = append(argv, s.Entrypoint...)
	argv = append(argv, s.Args...)
	env := make([]string, 0, len(image.ImageEnv)+len(bootstrap))
	for _, entry := range image.ImageEnv {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || strings.HasPrefix(key, "PLUGIN_") || key == "FLEXMODULE_PLUGIN" || strings.HasPrefix(key, "CHATANIUM_GVX_") {
			return gvxcontract.BridgeInit{}, errors.New("image environment collides with trusted bridge bootstrap")
		}
		env = append(env, entry)
	}
	for _, entry := range bootstrap {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			return gvxcontract.BridgeInit{}, errors.New("invalid bridge bootstrap environment")
		}
		switch key {
		case "FLEXMODULE_PLUGIN", "PLUGIN_PROTOCOL_VERSIONS", "PLUGIN_MULTIPLEX_GRPC", "PLUGIN_CLIENT_CERT", "PLUGIN_UNIX_SOCKET_DIR", "PLUGIN_UNIX_SOCKET_GROUP", "PLUGIN_MIN_PORT", "PLUGIN_MAX_PORT":
		default:
			return gvxcontract.BridgeInit{}, errors.New("unapproved bridge bootstrap environment")
		}
		env = append(env, entry)
	}
	workdir := image.Workdir
	if workdir == "" {
		workdir = "/"
	}
	init := gvxcontract.BridgeInit{Argv: argv, Env: env, Workdir: workdir, UID: s.UID, GID: s.GID, SocketDir: guestSocketDir, Roots: roots}
	if _, err := gvxipc.ValidateInit(init, controlLimit); err != nil {
		return gvxcontract.BridgeInit{}, err
	}
	return init, nil
}

// The two directions are independent, and each permits at most one DATA slab in
// flight. In particular a worker EOF only closes the guest's write half.
type stream struct {
	read, guestRead   *io.PipeReader
	write, guestWrite *io.PipeWriter
	departed          chan struct{}
	once              sync.Once
}

func newStream() *stream {
	r, gw := io.Pipe()
	gr, w := io.Pipe()
	return &stream{read: r, guestRead: gr, write: w, guestWrite: gw, departed: make(chan struct{})}
}

func (s *stream) Read(p []byte) (int, error)  { return s.read.Read(p) }
func (s *stream) Write(p []byte) (int, error) { return s.write.Write(p) }
func (s *stream) CloseWrite() error           { return s.write.Close() }
func (s *stream) Close() error {
	s.once.Do(func() { close(s.departed) })
	return errors.Join(s.read.Close(), s.CloseWrite())
}

func (s *stream) abort(err error) {
	_ = s.guestWrite.CloseWithError(err)
	_ = s.guestRead.CloseWithError(err)
}

func (s *stream) send(codec *gvxipc.Codec) error {
	var slab [gvxipc.MaxData]byte
	for {
		n, err := s.guestRead.Read(slab[:])
		if n > 0 {
			if e := codec.Write(gvxipc.Data, slab[:n]); e != nil {
				return e
			}
		}
		if errors.Is(err, io.EOF) {
			return codec.Write(gvxipc.Fin, nil)
		}
		if err != nil {
			return err
		}
	}
}

func (s *stream) receive(codec *gvxipc.Codec, controlLimit int, exited chan<- struct{}, completing *atomic.Bool) (host.ProcessExit, error) {
	var result host.ProcessExit
	for {
		typ, payload, err := codec.Read()
		if err != nil {
			if err == io.EOF && result.Kind != "" {
				return result, nil
			}
			return host.ProcessExit{}, err
		}
		switch typ {
		case gvxipc.Data:
			// A concurrently departing client no longer needs data. Continue to
			// validate framing to recover a real EXIT, subject to the drain budget.
			if _, err = s.guestWrite.Write(payload); err != nil && !errors.Is(err, io.ErrClosedPipe) {
				return host.ProcessExit{}, err
			}
		case gvxipc.Fin:
			_ = s.guestWrite.Close()
		case gvxipc.Exit:
			exit, err := gvxipc.DecodeExit(payload, controlLimit)
			if err != nil {
				return host.ProcessExit{}, err
			}
			result = host.ProcessExit{Kind: exit.Kind, Value: exit.Value}
			completing.Store(true)
			close(exited)
			s.abort(nil)
		case gvxipc.Error:
			return host.ProcessExit{}, bridgeFailure(payload, controlLimit)
		default:
			return host.ProcessExit{}, fmt.Errorf("%w: unexpected running frame %d", gvxipc.ErrInvalidFrame, typ)
		}
	}
}

func bridgeFailure(payload []byte, controlLimit int) error {
	failure, err := gvxipc.DecodeError(payload, controlLimit)
	if err != nil {
		return err
	}
	return fmt.Errorf("guest bridge error %s", failure.Code)
}
