//go:build linux

package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const controlVersion = 1

// The operation set is deliberately closed: there is no exec, SQL, arbitrary
// path, mount, firewall-expression, or Docker forwarding operation.
type controlRequest struct {
	Version         int          `json:"version"`
	Operation       string       `json:"operation"`
	EpochID         string       `json:"epoch_id,omitempty"`
	InstanceID      string       `json:"instance_id,omitempty"`
	Spec            *LaunchSpec  `json:"spec,omitempty"`
	Bootstrap       []string     `json:"bootstrap,omitempty"`
	SocketDirectory string       `json:"socket_directory,omitempty"`
	SocketName      string       `json:"socket_name,omitempty"`
	Egress          EgressPolicy `json:"egress,omitempty"`
	ImageDigest     string       `json:"image_digest,omitempty"`
}
type controlResponse struct {
	Version     int             `json:"version"`
	EpochID     string          `json:"epoch_id,omitempty"`
	Lease       *Lease          `json:"lease,omitempty"`
	ContainerID string          `json:"container_id,omitempty"`
	Exit        *Exit           `json:"exit,omitempty"`
	Error       *Error          `json:"error,omitempty"`
	Manifest    json.RawMessage `json:"manifest,omitempty"`
}

func strictJSON(data []byte, to any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(to); err != nil {
		return err
	}
	var rest any
	if err := d.Decode(&rest); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}
func peerIdentity(c *net.UnixConn) (*unix.Ucred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var inner error
	err = raw.Control(func(fd uintptr) { cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil {
		return nil, err
	}
	return cred, inner
}
func closeFiles(files []*os.File) {
	for _, f := range files {
		if f != nil {
			f.Close()
		}
	}
}
func receivePacket(c *net.UnixConn, max int) ([]byte, []*os.File, error) {
	data := make([]byte, max)
	oob := make([]byte, unix.CmsgSpace(4*3))
	n, on, flags, _, err := c.ReadMsgUnix(data, oob)
	if err != nil {
		return nil, nil, err
	}
	var files []*os.File
	messages, err := unix.ParseSocketControlMessage(oob[:on])
	if err == nil {
		for _, m := range messages {
			fds, e := unix.ParseUnixRights(&m)
			if e != nil {
				err = errors.Join(err, e)
				continue
			}
			for _, fd := range fds {
				unix.CloseOnExec(fd)
				files = append(files, os.NewFile(uintptr(fd), "supervisor-transfer"))
			}
		}
	}
	if err != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		closeFiles(files)
		return nil, nil, errors.New("invalid or oversized control packet")
	}
	if n == 0 {
		closeFiles(files)
		return nil, nil, io.EOF
	}
	return data[:n], files, nil
}
func sendPacket(c *net.UnixConn, max int, value any, files []*os.File) error {
	data, err := marshalControl(value)
	if err != nil {
		return err
	}
	if len(data) > max {
		return errors.New("control response exceeds configured limit")
	}
	var oob []byte
	if len(files) > 0 {
		fds := make([]int, len(files))
		for i, f := range files {
			fds[i] = int(f.Fd())
		}
		oob = unix.UnixRights(fds...)
	}
	n, on, err := c.WriteMsgUnix(data, oob, nil)
	if err != nil {
		return err
	}
	if n != len(data) || on != len(oob) {
		return io.ErrShortWrite
	}
	return nil
}
func marshalControl(value any) ([]byte, error) {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return b.Bytes()[:b.Len()-1], nil
}
func manifestPacketLimit(max int) (int, error) {
	envelope, err := marshalControl(controlResponse{Version: controlVersion, Manifest: json.RawMessage("null")})
	if err != nil {
		return 0, err
	}
	bound := max - (len(envelope) - len("null"))
	if bound < len("{}") {
		return 0, invalid("control packet bound cannot contain image manifest response")
	}
	return bound, nil
}

// Only the reconcile RPC may advertise pending cleanup as nonfatal admission.
// CREATE_OUTCOME_UNRESOLVED alone is insufficient: controlError also uses it for
// joins containing unrelated enforcement, storage, or transport failures.
func reconciliationError(err error) error {
	if unresolvedCleanupOnly(err) {
		return &Error{Reason: "HOST_RECONCILIATION_PENDING", Message: "only unresolved Docker creates remain; affected installations stay reserved while unrelated installations may run"}
	}
	return err
}

func controlError(err error) *Error {
	if errors.Is(err, ErrCreateUnresolved) {
		return &Error{Reason: "CREATE_OUTCOME_UNRESOLVED", Message: "submitted Docker create may still complete; resources remain reserved without automatic resubmission or release"}
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	if errors.Is(err, ErrCleanupIncomplete) {
		return &Error{Reason: "CLEANUP_INCOMPLETE", Message: "transient host resources remain owned"}
	}
	return &Error{Reason: "HOST_OPERATION_FAILED", Message: "trusted host operation failed"}
}
func validateSpec(s LaunchSpec) error {
	if s.ModuleID == "" || !safeID(s.InstanceID) || s.UID == 0 || s.GID == 0 {
		return invalid("module identity, fresh instance ID and nonroot UID/GID required")
	}
	if err := validateImageDigest(s.ImageDigest); err != nil {
		return err
	}
	if s.InitialEgress != EgressNone && s.InitialEgress != EgressPublicInternet {
		return invalid("initial egress topology must be explicit NONE or PUBLIC_INTERNET")
	}
	if len(s.Entrypoint) == 0 || !strings.HasPrefix(s.Entrypoint[0], "/") {
		return invalid("absolute image entrypoint required")
	}
	for _, args := range [][]string{s.Entrypoint, s.Args} {
		for _, a := range args {
			if strings.IndexByte(a, 0) >= 0 {
				return invalid("process argument contains NUL")
			}
		}
	}
	r := s.Resources
	for _, n := range []int64{r.NanoCPUs, r.MemoryBytes, r.Pids, r.PersistentBytes, r.ScratchBytes, r.PersistentInodes, r.ScratchInodes, r.ControlMessageMaxBytes, r.LogBufferBytes, r.LogFileMaxBytes, int64(r.LogRetainedFiles)} {
		if n <= 0 {
			return invalid("all resource and logging limits must be finite positive")
		}
	}
	if r.PersistentBytes%512 != 0 || r.ScratchBytes%512 != 0 || r.LogBufferBytes < r.ControlMessageMaxBytes {
		return invalid("inconsistent byte limits")
	}
	return nil
}
func safeID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func operationContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}
func validateRequest(r controlRequest) error {
	if r.Version != controlVersion {
		return invalid("unsupported supervisor protocol")
	}
	switch r.Operation {
	case "register":
		if r.EpochID != "" || r.InstanceID != "" || r.Spec != nil {
			return invalid("invalid register fields")
		}
	case "acquire":
		if r.Spec == nil {
			return invalid("missing launch spec")
		}
		if err := validateSpec(*r.Spec); err != nil {
			return err
		}
	case "create", "start", "wait", "terminate", "egress", "release", "capture":
		if !safeID(r.InstanceID) {
			return invalid("invalid instance ID")
		}
	case "reconcile":
	case "image_manifest":
		if err := validateImageDigest(r.ImageDigest); err != nil {
			return err
		}
	default:
		return invalid("unknown supervisor operation")
	}
	if r.Operation != "register" && !safeID(r.EpochID) {
		return invalid("invalid runtime epoch")
	}
	if r.Operation == "egress" && r.Egress != EgressNone && r.Egress != EgressPublicInternet {
		return invalid("invalid egress policy")
	}
	return nil
}
func pidfdPeer(f *os.File, cred *unix.Ucred) error {
	// fdinfo is kernel-generated and describes the received *held* descriptor.
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", f.Fd()))
	if err != nil {
		return err
	}
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		var pid int
		if _, e := fmt.Sscanf(line, "Pid:\t%d", &pid); e == nil {
			found = pid == int(cred.Pid)
			break
		}
	}
	if !found {
		return errors.New("pidfd does not identify actual Unix peer")
	}
	return unix.PidfdSendSignal(int(f.Fd()), 0, nil, 0)
}
