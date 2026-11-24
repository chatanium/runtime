package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/gvxipc"
	"github.com/thirdscam/chatanium/internal/portable/engine"
	"github.com/thirdscam/chatanium/internal/portable/process"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

const startupLogBytes = 2048

// startupLog retains only bounded diagnostics written before ROOTS_COMMIT.
// After that frame the module may write to stderr; its output is never echoed
// into the supervisor's startup report.
type startupLog struct {
	mu      sync.Mutex
	data    [startupLogBytes]byte
	size    int
	dropped bool
	stopped atomic.Bool
}

func (s *startupLog) Write(p []byte) (int, error) {
	if s.stopped.Load() {
		return len(p), nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.stopped.Load() {
		if len(p) >= len(s.data) {
			s.dropped = s.size != 0 || len(p) > len(s.data)
			copy(s.data[:], p[len(p)-len(s.data):])
			s.size = len(s.data)
		} else {
			if overflow := s.size + len(p) - len(s.data); overflow > 0 {
				copy(s.data[:], s.data[overflow:s.size])
				s.size -= overflow
				s.dropped = true
			}
			s.size += copy(s.data[s.size:], p)
		}
	}
	return len(p), nil
}

func (s *startupLog) stop() {
	s.mu.Lock()
	s.stopped.Store(true)
	s.mu.Unlock()
}

func (s *startupLog) quoted() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.data[:s.size]
	if s.dropped {
		// The first line can start in the middle of a credential. Never
		// print a truncated prefix that might defeat token redaction.
		if newline := bytes.IndexByte(p, '\n'); newline >= 0 {
			p = p[newline+1:]
		} else {
			return ""
		}
	}
	unframedHexTail := len(p) > 0 && hexByte(p[len(p)-1])
	p = bytes.TrimSpace(p)
	if len(p) == 0 {
		return ""
	}
	// The pinned GVX session token is a 64-digit hex string. Redact long
	// hex runs, including partial writes, without loading the token file.
	redacted := make([]byte, 0, len(p))
	for i := 0; i < len(p); {
		if !hexByte(p[i]) {
			redacted = append(redacted, p[i])
			i++
			continue
		}
		j := i + 1
		for j < len(p) && hexByte(p[j]) {
			j++
		}
		if j-i >= 16 || j == len(p) && unframedHexTail {
			redacted = append(redacted, "[redacted]"...)
		} else {
			redacted = append(redacted, p[i:j]...)
		}
		i = j
	}
	return strconv.QuoteToASCII(string(redacted))
}

func hexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// startupReason classifies the original local error without ever formatting
// its raw string, which could carry arguments, a filename, or peer input.
func startupReason(err error) string {
	switch {
	case errors.Is(err, engine.ErrUnsupportedTarget):
		return "UNSUPPORTED_TARGET"
	case errors.Is(err, engine.ErrCapabilityMissing):
		return "ENGINE_CAPABILITY_MISSING"
	case errors.Is(err, engine.ErrApprovalMismatch), errors.Is(err, store.ErrApprovalMismatch), errors.Is(err, store.ErrIdentity):
		return "APPROVAL_MISMATCH"
	case errors.Is(err, engine.ErrEgressRevoked), errors.Is(err, store.ErrEgressRevoked):
		return "EGRESS_REVOKED"
	case errors.Is(err, engine.ErrControlLost):
		return "GVX_CONTROL_LOST"
	case errors.Is(err, engine.ErrPeerExited), errors.Is(err, engine.ErrPeerClosing):
		return "GVX_PEER_EXITED"
	case errors.Is(err, engine.ErrExitUnconfirmed), errors.Is(err, process.ErrUnobserved), errors.Is(err, store.ErrCleanupPending):
		return "CLEANUP_PENDING"
	case errors.Is(err, gvxipc.ErrInvalidFrame):
		return "BRIDGE_PROTOCOL_ERROR"
	case errors.Is(err, store.ErrBudgetExceeded):
		return "BUDGET_EXCEEDED"
	case errors.Is(err, store.ErrVolumeBusy):
		return "VOLUME_BUSY"
	case errors.Is(err, store.ErrState):
		return "INVALID_RUN_STATE"
	case errors.Is(err, context.DeadlineExceeded):
		return "DEADLINE_EXCEEDED"
	case errors.Is(err, context.Canceled):
		return "CANCELLED"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "UNEXPECTED_EOF"
	case errors.Is(err, fs.ErrClosed), errors.Is(err, io.ErrClosedPipe):
		return "STREAM_CLOSED"
	case errors.Is(err, fs.ErrNotExist):
		return "FILE_NOT_FOUND"
	case errors.Is(err, fs.ErrPermission):
		return "PERMISSION_DENIED"
	}
	var exit *process.ExitError
	if errors.As(err, &exit) {
		return "NATIVE_EXIT"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return "OS_ERROR_" + strconv.FormatUint(uint64(errno), 10)
	}
	var path *os.PathError
	if errors.As(err, &path) {
		return "PATH_ERROR"
	}
	return fmt.Sprintf("STARTUP_FAILED (%T)", err)
}

// Read only the protocol magic on an already reaped failed startup, before
// any codec read. Never consume a successful guest's stream or echo frames.
func failedStartupStdout(i *instance) string {
	if i.pipes == nil || i.startupPhase != "authenticate-engine" && i.startupPhase != "record-engine" {
		return ""
	}
	pipe := i.pipes.output
	if err := pipe.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		return ""
	}
	var prefix [len(gvxcontract.BridgeMagic)]byte
	n, err := io.ReadFull(pipe, prefix[:])
	switch {
	case n == len(prefix) && string(prefix[:]) == gvxcontract.BridgeMagic:
		return "valid-magic"
	case n != 0:
		return "unexpected-bytes"
	case err == io.EOF:
		return "no-handshake"
	default:
		return ""
	}
}

func (b *Backend) reportStartupFailure(i *instance) {
	if b.opts.Diagnostics == nil || i.authorized || !i.openAttempted {
		return
	}
	err := i.startupErr
	if err == nil {
		err = context.Cause(i.ctx)
		if err == errStopped || err == errExited || err == nil {
			return
		}
	}
	stderr := i.startupLog.quoted()
	var native string
	if i.child != nil && i.child.Observed() {
		var status *process.ExitError
		if errors.As(i.child.Wait(), &status) {
			native = fmt.Sprintf(" native_exit=%d native_signal=%d", status.Code, status.Signal)
			if status.Code == 125 && status.Signal == 0 {
				if stdout := failedStartupStdout(i); stdout != "" {
					native += " gvx_stdout=" + stdout
				}
			}
		}
	}
	b.diagnosticsMu.Lock()
	defer b.diagnosticsMu.Unlock()
	if stderr == "" {
		_, _ = fmt.Fprintf(b.opts.Diagnostics, "sandbox startup: instance=%s phase=%s reason=%s%s\n", i.run.InstanceID, i.startupPhase, startupReason(err), native)
	} else {
		_, _ = fmt.Fprintf(b.opts.Diagnostics, "sandbox startup: instance=%s phase=%s reason=%s%s gvx_stderr=%s\n", i.run.InstanceID, i.startupPhase, startupReason(err), native, stderr)
	}
}
