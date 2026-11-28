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

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	sharedhost "github.com/thirdscam/chatanium/internal/host"
	"golang.org/x/sys/unix"
)

const controlVersion = gvxcontract.RuntimeControlVersion

// The operation set never accepts paths, commands or native ownership.
type controlRequest struct {
	Version        int                         `json:"version"`
	Operation      string                      `json:"operation"`
	EpochID        string                      `json:"epoch_id,omitempty"`
	InstanceID     string                      `json:"instance_id,omitempty"`
	Spec           *sharedhost.LaunchSpec                 `json:"spec,omitempty"`
	Bootstrap      []string                    `json:"bootstrap,omitempty"`
	RootInitResult *gvxcontract.RootInitResult `json:"root_init_result,omitempty"`
	Egress         sharedhost.EgressPolicy                `json:"egress,omitempty"`
	ImageDigest    string                      `json:"image_digest,omitempty"`
}
type controlResponse struct {
	Version          int                     `json:"version"`
	EpochID          string                  `json:"epoch_id,omitempty"`
	Lease            *sharedhost.Lease                  `json:"lease,omitempty"`
	Unit             *sharedhost.UnitIdentity           `json:"unit,omitempty"`
	Init             *gvxcontract.BridgeInit `json:"init,omitempty"`
	EndpointIdentity *EndpointIdentity       `json:"endpoint_identity,omitempty"`
	Exit             *sharedhost.ProcessExit            `json:"exit,omitempty"`
	Error            *sharedhost.Error                  `json:"error,omitempty"`
	Manifest         json.RawMessage         `json:"manifest,omitempty"`
}

func strictJSON(data []byte, to any) error {
	return gvxcontract.DecodeStrict(data, len(data), 32, to)
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
	oob := make([]byte, unix.CmsgSpace(4*6))
	n, on, flags, _, err := c.ReadMsgUnix(data, oob)
	if err != nil {
		return nil, nil, err
	}
	var files []*os.File
	messages, err := unix.ParseSocketControlMessage(oob[:on])
	if len(messages) > 1 {
		err = errors.New("extra ancillary records")
	}
	{
		for _, m := range messages {
			if m.Header.Level != unix.SOL_SOCKET || m.Header.Type != unix.SCM_RIGHTS {
				err = errors.New("unexpected ancillary record")
				continue
			}
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
		return &sharedhost.Error{Reason: "HOST_RECONCILIATION_PENDING", Message: "unresolved submissions remain reserved"}
	}
	return err
}

func controlError(err error) *sharedhost.Error {
	if errors.Is(err, ErrCreateUnresolved) {
		return &sharedhost.Error{Reason: "CREATE_OUTCOME_UNRESOLVED", Message: "submitted create remains reserved without automatic resubmission"}
	}
	var e *sharedhost.Error
	if errors.As(err, &e) {
		return e
	}
	if errors.Is(err, sharedhost.ErrCleanupIncomplete) {
		return &sharedhost.Error{Reason: "CLEANUP_INCOMPLETE", Message: "transient host resources remain owned"}
	}
	return &sharedhost.Error{Reason: "HOST_OPERATION_FAILED", Message: "trusted host operation failed"}
}
func validateSpec(s sharedhost.LaunchSpec) error { return validateLaunchSpec(s, true) }
func operationContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}
func validateRequest(r controlRequest) error {
	if r.Version != controlVersion {
		return invalid("unsupported runtime control version")
	}
	allowed := map[string]map[string]bool{
		"register":              {},
		"acquire":               {"epoch_id": true, "spec": true},
		"image_manifest":        {"epoch_id": true, "image_digest": true},
		"create":                {"epoch_id": true, "instance_id": true, "bootstrap": true},
		"start":                 {"epoch_id": true, "instance_id": true},
		"confirm_guest_storage": {"epoch_id": true, "instance_id": true, "root_init_result": true},
		"wait":                  {"epoch_id": true, "instance_id": true},
		"egress":                {"epoch_id": true, "instance_id": true, "egress": true},
		"terminate":             {"epoch_id": true, "instance_id": true},
		"release":               {"epoch_id": true, "instance_id": true},
		"reconcile":             {"epoch_id": true},
	}
	fields, ok := allowed[r.Operation]
	if !ok {
		return invalid("unknown runtime operation")
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	var present map[string]json.RawMessage
	if err = json.Unmarshal(raw, &present); err != nil {
		return err
	}
	for k := range present {
		if k != "version" && k != "operation" && !fields[k] {
			return invalid("field is not allowed for operation")
		}
	}
	if r.Operation != "register" && !safeID(r.EpochID) {
		return invalid("invalid runtime epoch")
	}
	if fields["instance_id"] && !safeID(r.InstanceID) {
		return invalid("invalid instance ID")
	}
	switch r.Operation {
	case "acquire":
		if r.Spec == nil {
			return invalid("missing launch spec")
		}
		return validateSpec(*r.Spec)
	case "image_manifest":
		return validateImageDigest(r.ImageDigest)
	case "confirm_guest_storage":
		if r.RootInitResult == nil {
			return invalid("missing root confirmation")
		}
	case "egress":
		if r.Egress != sharedhost.EgressNone && r.Egress != sharedhost.EgressPublicInternet {
			return invalid("invalid egress")
		}
	}
	return nil
}

// ValidateCreateResponse is called before any native service submission and
// again before transfer; the whole envelope includes base64 INIT roots.
func ValidateCreateResponse(p *StageProcess, max int) error {
	if p == nil {
		return errors.New("missing stage response")
	}
	raw, err := marshalControl(controlResponse{Version: controlVersion, Unit: &p.Unit, Init: &p.Init, EndpointIdentity: &p.EndpointIdentity})
	if err != nil {
		return err
	}
	if max <= 0 || len(raw) > max {
		return errors.New("complete Create response exceeds packet bound")
	}
	return nil
}

func decodeControlRequest(raw []byte, r *controlRequest) error {
	if err := strictJSON(raw, r); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	allowed := " version operation "
	switch r.Operation {
	case "register":
	case "acquire":
		allowed += "epoch_id spec "
	case "image_manifest":
		allowed += "epoch_id image_digest "
	case "create":
		allowed += "epoch_id instance_id bootstrap "
	case "confirm_guest_storage":
		allowed += "epoch_id instance_id root_init_result "
	case "egress":
		allowed += "epoch_id instance_id egress "
	case "start", "wait", "terminate", "release":
		allowed += "epoch_id instance_id "
	case "reconcile":
		allowed += "epoch_id "
	default:
		return invalid("unknown runtime operation")
	}
	for key := range fields {
		if !strings.Contains(allowed, " "+key+" ") {
			return invalid("unexpected operation field")
		}
	}
	return validateRequest(*r)
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

func validateControlResponse(raw []byte, operation string, fdCount int) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	allowed := " version "
	wantFD := 0
	if value, failed := fields["error"]; failed {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) || fdCount != 0 {
			return errors.New("invalid error response envelope")
		}
		for key := range fields {
			if key != "version" && key != "error" {
				return errors.New("unexpected error response field")
			}
		}
		return nil
	}
	switch operation {
	case "register":
		allowed += "epoch_id "
	case "acquire":
		allowed += "lease "
	case "image_manifest":
		allowed += "manifest "
	case "create":
		allowed += "unit init endpoint_identity "
		wantFD = 5
	case "wait":
		allowed += "exit "
	case "start", "confirm_guest_storage", "egress", "terminate", "release", "reconcile":
	default:
		return errors.New("unknown response operation")
	}
	if fdCount != wantFD {
		return errors.New("wrong control response descriptor count")
	}
	for key := range fields {
		if !strings.Contains(allowed, " "+key+" ") {
			return errors.New("unexpected response field")
		}
	}
	return nil
}
