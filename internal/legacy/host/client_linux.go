//go:build linux

package host

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	sharedhost "github.com/thirdscam/chatanium/internal/host"
	"golang.org/x/sys/unix"
)

// Client owns one epoch belonging to this actual process. Every operation opens
// its own authenticated packet connection so Wait cannot block kill/release.
type Client struct {
	config ClientConfig
	epoch  string
	mu     sync.RWMutex
	closed bool
}

func Dial(ctx context.Context, c ClientConfig) (*Client, error) {
	if c.SocketPath == "" || c.MaxMessageBytes <= 0 || c.OperationTimeout <= 0 {
		return nil, invalid("finite supervisor client configuration required")
	}
	client := &Client{config: c}
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return nil, prerequisite(err)
	}
	f := os.NewFile(uintptr(fd), "runtime-self-pidfd")
	defer f.Close()
	response, files, err := client.call(ctx, controlRequest{Operation: "register"}, []*os.File{f})
	closeFiles(files)
	if err != nil {
		return nil, err
	}
	if !safeID(response.EpochID) {
		return nil, errors.New("invalid supervisor epoch response")
	}
	client.epoch = response.EpochID
	return client, nil
}
func (c *Client) call(ctx context.Context, r controlRequest, send []*os.File) (controlResponse, []*os.File, error) {
	var response controlResponse
	c.mu.RLock()
	closed := c.closed
	c.mu.RUnlock()
	if closed {
		return response, nil, errors.New("supervisor client closed")
	}
	op, cancel := operationContext(ctx, c.config.OperationTimeout)
	defer cancel()
	d := net.Dialer{}
	connection, err := d.DialContext(op, "unixpacket", c.config.SocketPath)
	if err != nil {
		return response, nil, err
	}
	conn := connection.(*net.UnixConn)
	defer conn.Close()
	cred, err := peerIdentity(conn)
	if err != nil {
		return response, nil, err
	}
	if cred.Uid != c.config.SupervisorUID {
		return response, nil, errors.New("unauthorized supervisor peer")
	}
	deadline, _ := op.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return response, nil, err
	}
	// Cancellation closes the actual socket; a context wrapper alone is not a
	// cancellation mechanism for a blocked ReadMsgUnix/WriteMsgUnix.
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-op.Done():
			conn.Close()
		case <-stopped:
		}
	}()
	r.Version = controlVersion
	if r.Operation != "register" {
		r.EpochID = c.epoch
	}
	if err = sendPacket(conn, c.config.MaxMessageBytes, r, send); err != nil {
		return response, nil, err
	}
	data, files, err := receivePacket(conn, c.config.MaxMessageBytes)
	if err != nil {
		return response, nil, err
	}
	if err = strictJSON(data, &response); err != nil {
		closeFiles(files)
		return response, nil, err
	}
	if response.Version != controlVersion {
		closeFiles(files)
		return response, nil, errors.New("unsupported supervisor response")
	}
	if err = validateControlResponse(data, r.Operation, len(files)); err != nil {
		closeFiles(files)
		return response, nil, err
	}
	if response.Error != nil {
		closeFiles(files)
		return response, nil, response.Error
	}
	return response, files, nil
}
func (c *Client) ordinary(ctx context.Context, r controlRequest) (controlResponse, error) {
	out, files, err := c.call(ctx, r, nil)
	if len(files) != 0 {
		closeFiles(files)
		return out, errors.New("unexpected supervisor response descriptors")
	}
	return out, err
}
func (c *Client) Acquire(ctx context.Context, s sharedhost.LaunchSpec) (sharedhost.Lease, error) {
	if err := validateSpec(s); err != nil {
		return sharedhost.Lease{}, err
	}
	out, err := c.ordinary(ctx, controlRequest{Operation: "acquire", Spec: &s})
	if err != nil {
		return sharedhost.Lease{}, err
	}
	if out.Lease == nil || out.Lease.Spec.InstanceID != s.InstanceID || out.Lease.Spec.ModuleID != s.ModuleID || out.Lease.Ownership.EpochID != c.epoch {
		return sharedhost.Lease{}, errors.New("supervisor lease identity mismatch")
	}
	return *out.Lease, nil
}

// ImageManifest retrieves only the declaration from one exact local image.
// It is untrusted requirements data, never an approval or published grant.
func (c *Client) ImageManifest(ctx context.Context, digest string) ([]byte, error) {
	if err := validateImageDigest(digest); err != nil {
		return nil, err
	}
	out, err := c.ordinary(ctx, controlRequest{Operation: "image_manifest", ImageDigest: digest})
	if err != nil {
		return nil, err
	}
	bound, err := manifestPacketLimit(c.config.MaxMessageBytes)
	if err != nil {
		return nil, err
	}
	if len(out.Manifest) == 0 || len(out.Manifest) > bound {
		return nil, errors.New("supervisor returned missing or oversized image declaration")
	}
	return out.Manifest, nil
}
func (c *Client) Create(ctx context.Context, id string, bootstrap []string) (*StageProcess, error) {
	out, files, err := c.call(ctx, controlRequest{Operation: "create", InstanceID: id, Bootstrap: bootstrap}, nil)
	if err != nil {
		closeFiles(files)
		return nil, err
	}
	if len(files) != 5 || out.Unit == nil || out.Init == nil || out.EndpointIdentity == nil {
		closeFiles(files)
		return nil, errors.New("incomplete five-FD stage response")
	}
	p := &StageProcess{Unit: *out.Unit, Init: *out.Init, EndpointIdentity: *out.EndpointIdentity, Stdin: files[0], Stdout: files[1], Stderr: files[2], Listener: files[3], Endpoint: files[4]}
	if err = validateStageDescriptors(p); err != nil {
		closeFiles(files)
		return nil, err
	}
	payload, err := gvxcontract.DecodeRootManifest(p.Init.Roots, c.config.MaxMessageBytes, 32)
	if err != nil || payload.EpochID != c.epoch || payload.InstanceID != id || !validUnit(p.Unit) {
		closeFiles(files)
		return nil, errors.New("stage response binding mismatch")
	}
	return p, nil
}
func (c *Client) ConfirmGuestStorage(ctx context.Context, id string, result gvxcontract.RootInitResult) error {
	_, err := c.ordinary(ctx, controlRequest{Operation: "confirm_guest_storage", InstanceID: id, RootInitResult: &result})
	return err
}
func (c *Client) Start(ctx context.Context, id string) error {
	_, err := c.ordinary(ctx, controlRequest{Operation: "start", InstanceID: id})
	return err
}
func (c *Client) Wait(ctx context.Context, id string) (sharedhost.ProcessExit, error) {
	for {
		out, err := c.ordinary(ctx, controlRequest{Operation: "wait", InstanceID: id})
		var e *sharedhost.Error
		if errors.As(err, &e) && e.Reason == "WAIT_PENDING" {
			if ctx.Err() != nil {
				return sharedhost.ProcessExit{}, ctx.Err()
			}
			continue
		}
		if err != nil {
			return sharedhost.ProcessExit{}, err
		}
		if out.Exit == nil || !validProcessExit(*out.Exit) {
			return sharedhost.ProcessExit{}, errors.New("supervisor omitted native exit")
		}
		return *out.Exit, nil
	}
}
func (c *Client) Terminate(ctx context.Context, id string) error {
	_, err := c.ordinary(ctx, controlRequest{Operation: "terminate", InstanceID: id})
	return err
}
func (c *Client) SetEgress(ctx context.Context, id string, p sharedhost.EgressPolicy) error {
	_, err := c.ordinary(ctx, controlRequest{Operation: "egress", InstanceID: id, Egress: p})
	return err
}
func (c *Client) Release(ctx context.Context, id string) error {
	_, err := c.ordinary(ctx, controlRequest{Operation: "release", InstanceID: id})
	return err
}
func (c *Client) Reconcile(ctx context.Context) error {
	_, err := c.ordinary(ctx, controlRequest{Operation: "reconcile"})
	return err
}
func (c *Client) Close() error    { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }
func (c *Client) EpochID() string { return c.epoch }

// Timeout is available to the trusted runner for independent finite teardown.
func (c *Client) Timeout() time.Duration { return c.config.OperationTimeout }

func validateStageDescriptors(p *StageProcess) error {
	for i, f := range []*os.File{p.Stdin, p.Stdout, p.Stderr} {
		if f == nil {
			return errors.New("missing pipe descriptor")
		}
		var st unix.Stat_t
		if err := unix.Fstat(int(f.Fd()), &st); err != nil {
			return err
		}
		flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
		if err != nil {
			return err
		}
		want := unix.O_RDONLY
		if i == 0 {
			want = unix.O_WRONLY
		}
		if st.Mode&unix.S_IFMT != unix.S_IFIFO || flags&unix.O_ACCMODE != want {
			return errors.New("invalid stage pipe type or access direction")
		}
	}
	if p.Listener == nil || p.Endpoint == nil {
		return errors.New("missing endpoint descriptors")
	}
	fd := int(p.Listener.Fd())
	for _, v := range []struct{ opt, want int }{{unix.SO_DOMAIN, unix.AF_UNIX}, {unix.SO_TYPE, unix.SOCK_STREAM}, {unix.SO_ACCEPTCONN, 1}} {
		got, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, v.opt)
		if err != nil {
			return err
		}
		if got != v.want {
			return errors.New("invalid listening Unix endpoint")
		}
	}
	addr, err := unix.Getsockname(fd)
	if err != nil {
		return err
	}
	a, ok := addr.(*unix.SockaddrUnix)
	if !ok || a.Name != p.EndpointIdentity.Path {
		return errors.New("listener binding mismatch")
	}
	flags, err := unix.FcntlInt(p.Endpoint.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	var st unix.Stat_t
	if err = unix.Fstat(int(p.Endpoint.Fd()), &st); err != nil {
		return err
	}
	e := p.EndpointIdentity
	if flags&unix.O_PATH == 0 || st.Mode&unix.S_IFMT != unix.S_IFSOCK || uint64(st.Dev) != e.SocketDev || st.Ino != e.SocketIno || st.Uid != e.UID || st.Gid != e.GID || st.Mode&07777 != e.Mode {
		return errors.New("filesystem socket O_PATH identity mismatch")
	}
	link, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", p.Endpoint.Fd()))
	if err != nil {
		return err
	}
	if strings.TrimSuffix(link, " (deleted)") != e.Path {
		return errors.New("O_PATH does not pin the named filesystem socket")
	}
	var directory unix.Stat_t
	if err = unix.Stat(e.Directory, &directory); err != nil {
		return err
	}
	if uint64(directory.Dev) != e.DirectoryDev || directory.Ino != e.DirectoryIno {
		return errors.New("endpoint parent identity mismatch")
	}
	return nil
}
