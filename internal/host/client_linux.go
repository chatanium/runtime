//go:build linux

package host

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

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
func (c *Client) Acquire(ctx context.Context, s LaunchSpec) (Lease, error) {
	if err := validateSpec(s); err != nil {
		return Lease{}, err
	}
	out, err := c.ordinary(ctx, controlRequest{Operation: "acquire", Spec: &s})
	if err != nil {
		return Lease{}, err
	}
	if out.Lease == nil || out.Lease.Spec.InstanceID != s.InstanceID || out.Lease.Spec.ModuleID != s.ModuleID || out.Lease.Ownership.EpochID != c.epoch {
		return Lease{}, errors.New("supervisor lease identity mismatch")
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
func (c *Client) Create(ctx context.Context, id string, bootstrap []string, hostSocketDir string) (*Container, error) {
	out, files, err := c.call(ctx, controlRequest{Operation: "create", InstanceID: id, Bootstrap: bootstrap, SocketDirectory: hostSocketDir}, nil)
	if err != nil {
		return nil, err
	}
	if len(files) != 2 || out.ContainerID == "" {
		closeFiles(files)
		return nil, errors.New("supervisor omitted actual container streams")
	}
	return &Container{ID: out.ContainerID, Stdout: files[0], Stderr: files[1]}, nil
}
func (c *Client) Start(ctx context.Context, id string) error {
	_, err := c.ordinary(ctx, controlRequest{Operation: "start", InstanceID: id})
	return err
}
func (c *Client) Wait(ctx context.Context, id string) (Exit, error) {
	for {
		out, err := c.ordinary(ctx, controlRequest{Operation: "wait", InstanceID: id})
		var e *Error
		if errors.As(err, &e) && e.Reason == "WAIT_PENDING" {
			if ctx.Err() != nil {
				return Exit{}, ctx.Err()
			}
			continue
		}
		if err != nil {
			return Exit{}, err
		}
		if out.Exit == nil {
			return Exit{}, errors.New("supervisor omitted container exit")
		}
		return *out.Exit, nil
	}
}
func (c *Client) Terminate(ctx context.Context, id string) error {
	_, err := c.ordinary(ctx, controlRequest{Operation: "terminate", InstanceID: id})
	return err
}
func (c *Client) SetEgress(ctx context.Context, id string, p EgressPolicy) error {
	_, err := c.ordinary(ctx, controlRequest{Operation: "egress", InstanceID: id, Egress: p})
	return err
}
func (c *Client) CaptureSocket(ctx context.Context, id, name string) (*os.File, error) {
	_, files, err := c.call(ctx, controlRequest{Operation: "capture", InstanceID: id, SocketName: name}, nil)
	if err != nil {
		return nil, err
	}
	if len(files) != 1 {
		closeFiles(files)
		return nil, errors.New("supervisor omitted captured socket descriptor")
	}
	return files[0], nil
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
