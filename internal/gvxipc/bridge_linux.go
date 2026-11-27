//go:build linux

package gvxipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"golang.org/x/sys/unix"
)

func BootstrapLimits() (Limits, time.Duration, error) {
	control, e := strconv.ParseInt(os.Getenv("CHATANIUM_GVX_CONTROL_MAX_BYTES"), 10, 64)
	if e != nil {
		return Limits{}, 0, e
	}
	logs, e := strconv.ParseInt(os.Getenv("CHATANIUM_GVX_LOG_BUFFER_BYTES"), 10, 64)
	if e != nil {
		return Limits{}, 0, e
	}
	ns, e := strconv.ParseInt(os.Getenv("CHATANIUM_GVX_STARTUP_TIMEOUT_NS"), 10, 64)
	if e != nil || ns <= 0 {
		return Limits{}, 0, errors.New("finite controller startup timeout required")
	}
	l := Limits{control, logs}
	return l, time.Duration(ns), Workspace(l)
}

// ReportBootstrapFailure reports a fixed, caller-owned stage name and, if
// available, its errno. Never print an error's text, argv, or environment.
func ReportBootstrapFailure(w io.Writer, stage string, err error) {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		_, _ = fmt.Fprintf(w, "gvx-guest-bridge: bootstrap stage=%s errno=%d\n", stage, errno)
		return
	}
	_, _ = fmt.Fprintf(w, "gvx-guest-bridge: bootstrap stage=%s\n", stage)
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}
func copyDiagnostics(w io.Writer, r io.Reader) error {
	slab := make([]byte, LogSlab)
	for {
		n, e := r.Read(slab)
		if n > 0 {
			if err := writeFull(w, slab[:n]); err != nil {
				return err
			}
		}
		if e != nil {
			if e == io.EOF {
				return nil
			}
			return e
		}
	}
}
func sendFailure(c *Codec, code string) {
	p, _ := json.Marshal(ErrorPayload{Code: code, Message: "guest bridge failed closed"})
	_ = c.Write(Error, p)
}

func rejectPortableInit(c *Codec, err error) {
	message := err.Error()
	if len(message) <= 1024 {
		p, e := json.Marshal(ErrorPayload{Code: "INVALID_INIT", Message: message})
		if e == nil && len(p) <= c.max {
			_ = c.Write(Error, p)
			return
		}
	}
	sendFailure(c, "INVALID_INIT")
}

type socketCloseError struct{ err error }

func (e socketCloseError) Error() string { return e.err.Error() }
func (e socketCloseError) Unwrap() error { return e.err }
func expectedSocketClose(err error) bool {
	var socketErr socketCloseError
	return errors.As(err, &socketErr) && (errors.Is(socketErr.err, unix.EPIPE) || errors.Is(socketErr.err, net.ErrClosed) || errors.Is(socketErr.err, os.ErrClosed))
}

type startupFailure struct {
	code string
	err  error
}

func (e startupFailure) Error() string { return e.err.Error() }
func (e startupFailure) Unwrap() error { return e.err }
func failureCode(err error) string {
	var failure startupFailure
	if errors.As(err, &failure) {
		return failure.code
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "STARTUP_TIMEOUT"
	}
	if errors.Is(err, ErrInvalidFrame) {
		return "INVALID_FRAME"
	}
	return "IO_FAILED"
}

func pinGuestSocket(v gvxcontract.BridgeInit, path string) (*os.File, error) {
	dir, e := openDirectory(v.SocketDir)
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	var ds unix.Stat_t
	if e = unix.Fstat(int(dir.Fd()), &ds); e != nil {
		return nil, e
	}
	if ds.Uid != v.UID || ds.Gid != v.GID || ds.Mode&07777 != 0700 {
		return nil, errors.New("guest socket directory identity mismatch")
	}
	fd, e := unix.Openat(int(dir.Fd()), path[len(v.SocketDir)+1:], unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "guest-primary-endpoint")
	var st unix.Stat_t
	e = unix.Fstat(fd, &st)
	if e != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != v.UID || st.Gid != v.GID || st.Mode&07777 != 0660 {
		f.Close()
		return nil, errors.New("guest primary socket identity mismatch")
	}
	return f, nil
}

// RunGuest returns the child's ordinary status, 128+signal, or 125 for any
// bootstrap/protocol failure. stdout is exclusively the private framed stream.
func RunGuest(ctx context.Context, input, output, diagnostics *os.File, l Limits, startupTimeout time.Duration) int {
	return runGuest(ctx, input, output, diagnostics, l, startupTimeout, false)
}

// RunPortableGuest requires a portable-v2 manifest and uses only guest mounts
// to prepare the approved ext4lite roots before starting the nonroot module.
func RunPortableGuest(ctx context.Context, input, output, diagnostics *os.File, l Limits, startupTimeout time.Duration) int {
	return runGuest(ctx, input, output, diagnostics, l, startupTimeout, true)
}

func runGuest(ctx context.Context, input, output, diagnostics *os.File, l Limits, startupTimeout time.Duration, portable bool) int {
	startupDeadline := time.Now().Add(startupTimeout)
	failEarly := func(stage string, err error) int {
		if portable {
			ReportBootstrapFailure(diagnostics, stage, err)
		}
		return 125
	}
	input, e := pollableFile(input, true)
	if e != nil {
		return failEarly("stdin-poll", e)
	}
	defer input.Close()
	if !portable {
		output, e = pollableFile(output, false)
		if e != nil {
			return 125
		}
		diagnostics, e = pollableFile(diagnostics, false)
		if e != nil {
			return 125
		}
	}
	// Pinned GVX's non-TTY guest stdout and stderr do not support epoll,
	// even over host pipes. Keep those descriptors blocking; the supervisor
	// drains their host ends and terminates the engine at its startup deadline.
	defer output.Close()
	defer diagnostics.Close()
	c, e := NewCodec(input, output, Guest, l)
	if e != nil {
		return failEarly("codec", e)
	}
	if startupTimeout <= 0 {
		return failEarly("startup-timeout", nil)
	}
	var stopping atomic.Bool
	var connMu sync.Mutex
	var conn *net.UnixConn
	closeSocket := func() {
		connMu.Lock()
		if conn != nil {
			conn.Close()
		}
		connMu.Unlock()
	}
	timedOut := make(chan struct{})
	var timeoutOnce sync.Once
	startupTimer := time.AfterFunc(time.Until(startupDeadline), func() { timeoutOnce.Do(func() { close(timedOut) }); input.Close(); output.Close(); closeSocket() })
	defer startupTimer.Stop()
	stopContext := context.AfterFunc(ctx, func() { input.Close(); output.Close(); closeSocket() })
	defer stopContext()
	if e = c.SendMagic(); e != nil {
		return failEarly("magic-write", e)
	}
	if e = c.ReadMagic(); e != nil {
		return failEarly("magic-read", e)
	}
	typ, raw, e := c.Read()
	if e != nil || typ != Init {
		sendFailure(c, "INVALID_INIT")
		return 125
	}
	var init gvxcontract.BridgeInit
	if e = gvxcontract.DecodeStrict(raw, c.max, 16, &init); e != nil {
		sendFailure(c, "INVALID_INIT")
		return 125
	}
	rejectInit := func(err error) {
		if portable {
			rejectPortableInit(c, err)
		} else {
			sendFailure(c, "INVALID_INIT")
		}
	}
	roots, e := ValidateInit(init, c.max)
	if e != nil {
		rejectInit(e)
		return 125
	}
	wantVersion := uint8(gvxcontract.RootPayloadVersion)
	if portable {
		wantVersion = gvxcontract.PortableRootPayloadVersion
	}
	if roots.Version != wantVersion {
		rejectInit(errors.New("root manifest version does not match guest bridge entrypoint"))
		return 125
	}
	var result gvxcontract.RootInitResult
	var rootFDs []*os.File
	var finalRoots [3]guestMountDir
	if portable {
		result, rootFDs, e = initializePortableRoots(init, roots, &finalRoots)
	} else {
		result, rootFDs, e = initializeRoots(init, roots)
	}
	if e != nil {
		rejectInit(e)
		return 125
	}
	defer func() { _ = closeRootFDs(rootFDs) }()
	ready, e := json.Marshal(result)
	if e != nil || c.Write(RootsReady, ready) != nil {
		return 125
	}
	typ, _, e = c.Read()
	if e != nil || typ != RootsCommit {
		sendFailure(c, "INVALID_INIT")
		return 125
	}
	if e = dropPrivileges(init.UID, init.GID); e != nil {
		rejectInit(fmt.Errorf("drop all guest bridge thread privileges: %w", e))
		return 125
	}
	if portable {
		if e = verifyPortableRootAccess(roots.Roots, &finalRoots); e != nil {
			rejectInit(e)
			return 125
		}
	}
	e = closeRootFDs(rootFDs)
	rootFDs = nil
	if portable {
		if e != nil {
			rejectInit(fmt.Errorf("close guest initialization FDs: %w", e))
			return 125
		}
		// Explicitly closed every root pin. Also exclude any unexpected
		// inherited descriptor from the app's exec; only its new stdio is passed.
		if e = unix.CloseRange(3, uint(^uint32(0)), unix.CLOSE_RANGE_CLOEXEC); e != nil {
			rejectInit(fmt.Errorf("isolate guest module descriptors: %w", e))
			return 125
		}
	}
	if e = os.Mkdir(init.SocketDir, 0700); e != nil {
		sendFailure(c, "INVALID_INIT")
		return 125
	}
	// All inherited bootstrap environment is intentionally replaced, not merged.
	child := exec.Command(init.Argv[0], init.Argv[1:]...)
	child.Env = init.Env
	child.Dir = init.Workdir
	null, e := os.Open(os.DevNull)
	if e != nil {
		sendFailure(c, "CHILD_FAILED")
		return 125
	}
	defer null.Close()
	child.Stdin = null
	stdout, outW, e := os.Pipe()
	if e != nil {
		return 125
	}
	defer stdout.Close()
	stderr, errW, e := os.Pipe()
	if e != nil {
		outW.Close()
		return 125
	}
	defer stderr.Close()
	child.Stdout = outW
	child.Stderr = errW
	if portable {
		e = ctx.Err()
		if e == nil && !time.Now().Before(startupDeadline) {
			e = context.DeadlineExceeded
		}
	}
	if e == nil {
		e = child.Start()
	}
	if e != nil {
		outW.Close()
		errW.Close()
		code := "CHILD_FAILED"
		if errors.Is(e, context.DeadlineExceeded) {
			code = "STARTUP_TIMEOUT"
		}
		sendFailure(c, code)
		return 125
	}
	outW.Close()
	errW.Close()
	defer child.Process.Kill()
	childDone := make(chan error, 1)
	go func() { childDone <- child.Wait() }()
	failures := make(chan error, 4)
	report := func(err error) {
		if err != nil && (!stopping.Load() || errors.Is(err, ErrInvalidFrame)) {
			select {
			case failures <- err:
			default:
			}
		}
	}
	var pumps sync.WaitGroup
	diagnosticWriter := &lockedWriter{w: diagnostics}
	pumps.Add(1)
	go func() { defer pumps.Done(); report(copyDiagnostics(diagnosticWriter, stderr)) }()
	type handshakeResult struct {
		line []byte
		err  error
	}
	hs := make(chan handshakeResult, 1)
	pumps.Add(1)
	go func() {
		defer pumps.Done()
		reader := bufio.NewReaderSize(stdout, c.max+1)
		line, err := reader.ReadSlice('\n')
		if err != nil {
			hs <- handshakeResult{err: err}
			return
		}
		hs <- handshakeResult{line: append([]byte(nil), line...)}
		report(copyDiagnostics(diagnosticWriter, reader))
	}()
	var line []byte
	var waitErr error
	var childExited bool
	select {
	case h := <-hs:
		line = h.line
		if h.err != nil {
			e = startupFailure{"INVALID_HANDSHAKE", h.err}
		}
	case waitErr = <-childDone:
		childExited = true
		e = startupFailure{"CHILD_FAILED", errors.New("child exited before handshake")}
	case e = <-failures:
	case <-timedOut:
		e = context.DeadlineExceeded
	case <-ctx.Done():
		e = ctx.Err()
	}
	var pin *os.File
	pinSafeToClose := false
	defer func() {
		if pin != nil && pinSafeToClose {
			pin.Close()
		}
	}()
	if e == nil {
		var path string
		path, e = ValidateHandshake(line, init.SocketDir)
		if e == nil {
			pin, e = pinGuestSocket(init, path)
		}
		if e != nil {
			e = startupFailure{"INVALID_HANDSHAKE", e}
		}
	}
	if e == nil {
		e = c.Write(Handshake, line)
	}
	if e == nil {
		pumps.Add(1)
		go func() {
			defer pumps.Done()
			for {
				typ, payload, err := c.Read()
				if err != nil {
					report(err)
					return
				}
				switch typ {
				case Open:
					dialCtx, cancel := context.WithDeadline(ctx, startupDeadline)
					d := net.Dialer{}
					nc, err := d.DialContext(dialCtx, "unix", fmt.Sprintf("/proc/self/fd/%d", pin.Fd()))
					cancel()
					if err != nil {
						report(startupFailure{"OPEN_FAILED", err})
						return
					}
					uc, ok := nc.(*net.UnixConn)
					if !ok {
						nc.Close()
						report(startupFailure{"OPEN_FAILED", errors.New("non-Unix guest socket")})
						return
					}
					connMu.Lock()
					if stopping.Load() {
						uc.Close()
						connMu.Unlock()
						return
					}
					conn = uc
					connMu.Unlock()
					if err = c.Write(OpenOK, nil); err != nil {
						report(err)
						return
					}
					startupTimer.Stop()
					pumps.Add(1)
					go func() {
						defer pumps.Done()
						slab := make([]byte, MaxData)
						for {
							n, err := uc.Read(slab)
							if n > 0 {
								if stopping.Load() {
									return
								}
								if er := c.Write(Data, slab[:n]); er != nil {
									report(er)
									return
								}
							}
							if err != nil {
								if err == io.EOF {
									if !stopping.Load() {
										report(c.Write(Fin, nil))
									}
								} else {
									report(socketCloseError{err})
								}
								return
							}
						}
					}()
				case Data:
					connMu.Lock()
					uc := conn
					connMu.Unlock()
					if uc == nil {
						report(errors.New("DATA without guest connection"))
						return
					}
					if err = writeFull(uc, payload); err != nil {
						report(socketCloseError{err})
						return
					}
				case Fin:
					connMu.Lock()
					uc := conn
					connMu.Unlock()
					if uc == nil {
						report(errors.New("FIN without guest connection"))
						return
					}
					if err = uc.CloseWrite(); err != nil {
						report(socketCloseError{err})
					}
				case Error:
					_, err = DecodeError(payload, c.max)
					if err == nil {
						err = errors.New("host closed bridge with ERROR")
					}
					report(err)
					return
				default:
					report(errors.New("unexpected guest input frame"))
					return
				}
			}
		}()
		select {
		case waitErr = <-childDone:
			childExited = true
		case e = <-failures:
		case <-timedOut:
			e = context.DeadlineExceeded
		case <-ctx.Done():
			e = ctx.Err()
		}
	}
	if expectedSocketClose(e) && !childExited {
		select {
		case waitErr = <-childDone:
			childExited = true
			e = nil
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			e = ctx.Err()
		}
	}
	// Stop DATA before EXIT, unblock every physical pump, and bound descendant
	// output drains. An earlier protocol error always wins a cleanup EOF/EPIPE.
	stopping.Store(true)
	startupTimer.Stop()
	cleanupTimer := time.AfterFunc(2*time.Second, func() {
		input.Close()
		output.Close()
		diagnostics.Close()
		stdout.Close()
		stderr.Close()
		closeSocket()
	})
	defer cleanupTimer.Stop()
	_ = input.SetReadDeadline(time.Now())
	closeSocket()
	if !childExited {
		child.Process.Kill()
		select {
		case waitErr = <-childDone:
			childExited = true
		case <-time.After(2 * time.Second):
			e = errors.Join(e, errors.New("child join uncertain"))
		}
	}
	joined := make(chan struct{})
	go func() { pumps.Wait(); close(joined) }()
	select {
	case <-joined:
		pinSafeToClose = true
	case <-time.After(2 * time.Second):
		stdout.Close()
		stderr.Close()
		output.Close()
		// The process exit, not an uncertain goroutine join, releases this pin.
		e = errors.Join(e, errors.New("guest pump join timeout"))
	}
drainFailures:
	for {
		select {
		case err := <-failures:
			if !childExited || !expectedSocketClose(err) {
				e = errors.Join(e, err)
			}
		default:
			break drainFailures
		}
	}
	if e != nil || !childExited {
		sendFailure(c, failureCode(e))
		return 125
	}
	var status ExitPayload
	if waitErr == nil {
		status = ExitPayload{Kind: "exit", Value: 0}
	} else {
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			sendFailure(c, "CHILD_FAILED")
			return 125
		}
		ws, ok := exitErr.Sys().(syscall.WaitStatus)
		if !ok {
			sendFailure(c, "CHILD_FAILED")
			return 125
		}
		if ws.Signaled() {
			status = ExitPayload{Kind: "signal", Value: uint32(ws.Signal())}
		} else {
			status = ExitPayload{Kind: "exit", Value: uint32(ws.ExitStatus())}
		}
	}
	if status.Validate() != nil {
		sendFailure(c, "CHILD_FAILED")
		return 125
	}
	payload, _ := json.Marshal(status)
	if c.Write(Exit, payload) != nil {
		return 125
	}
	if status.Kind == "signal" {
		return 128 + int(status.Value)
	}
	return int(status.Value)
}

func pollableFile(original *os.File, read bool) (*os.File, error) {
	fd, e := unix.FcntlInt(original.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	if e = unix.SetNonblock(fd, true); e != nil {
		unix.Close(fd)
		return nil, e
	}
	f := os.NewFile(uintptr(fd), original.Name())
	if f == nil {
		unix.Close(fd)
		return nil, errors.New("cannot wrap guest stdio")
	}
	if read {
		e = f.SetReadDeadline(time.Time{})
	} else {
		e = f.SetWriteDeadline(time.Time{})
	}
	if e != nil {
		f.Close()
		return nil, e
	}
	original.Close()
	return f, nil
}
