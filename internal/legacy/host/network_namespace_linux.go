//go:build linux

package host

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// Mount and link effects belong to the native owner/PID1 namespace, never a
// helper-private mount tree. Do not attempt to change global propagation.
func networkHostNamespaces() error {
	tid := unix.Gettid()
	for _, kind := range []string{"mnt", "net"} {
		var local, host unix.Stat_t
		if err := unix.Stat(fmt.Sprintf("/proc/self/task/%d/ns/%s", tid, kind), &local); err != nil {
			return err
		}
		if err := unix.Stat("/proc/1/ns/"+kind, &host); err != nil {
			return err
		}
		if local.Dev != host.Dev || local.Ino != host.Ino {
			return prerequisite(errors.New("network owner must share PID1 mount and network namespaces"))
		}
	}
	return nil
}

type nativeNamespaceResult struct {
	pin *os.File
	err error
}
type nativeNamespaceUncertain struct{ cause error }

func (e *nativeNamespaceUncertain) Error() string { return e.cause.Error() }
func (e *nativeNamespaceUncertain) Unwrap() error { return e.cause }
func networkNewNamespace(ctx context.Context) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make(chan nativeNamespaceResult, 1)
	go func() {
		runtime.LockOSThread()
		restored := true
		defer func() {
			if restored {
				runtime.UnlockOSThread()
			}
		}()
		// A goroutine exiting while locked destroys its OS thread. In particular a
		// failed restoration must NEVER return a namespace-contaminated thread to Go.
		if err := networkHostNamespaces(); err != nil {
			result <- nativeNamespaceResult{err: err}
			return
		}
		original, err := unix.Open(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			result <- nativeNamespaceResult{err: err}
			return
		}
		defer unix.Close(original)
		if err = unix.Unshare(unix.CLONE_NEWNET); err != nil {
			result <- nativeNamespaceResult{err: err}
			return
		}
		restored = false
		created, openErr := unix.Open(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		restoreErr := unix.Setns(original, unix.CLONE_NEWNET)
		if restoreErr == nil {
			var before, after unix.Stat_t
			restoreErr = unix.Fstat(original, &before)
			if restoreErr == nil {
				restoreErr = unix.Stat(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()), &after)
			}
			if restoreErr == nil && (before.Dev != after.Dev || before.Ino != after.Ino) {
				restoreErr = errors.New("network namespace restoration readback mismatch")
			}
			restored = restoreErr == nil
		}
		if openErr != nil || restoreErr != nil {
			if created >= 0 {
				_ = unix.Close(created)
			}
			result <- nativeNamespaceResult{err: errors.Join(openErr, restoreErr)}
			return
		}
		result <- nativeNamespaceResult{pin: os.NewFile(uintptr(created), "owned-network-namespace")}
	}()
	select {
	case done := <-result:
		return done.pin, done.err
	case <-ctx.Done():
		// Namespace acquisition has no pathname/mount effects. A late transient FD
		// is closed rather than published after the original operation budget.
		go func() {
			done := <-result
			if done.pin != nil {
				_ = done.pin.Close()
			}
		}()
		return nil, &nativeNamespaceUncertain{ctx.Err()}
	}
}

func (n *Network) createNativeNamespace(ctx context.Context, a *networkAllocation) error {
	if err := networkHostNamespaces(); err != nil {
		return err
	}
	if err := networkTrustedDirectory(filepath.Dir(a.Record.NetnsPath)); err != nil {
		return err
	}
	// The generation/path intent is already SUBMITTED. Observe the exclusive
	// placeholder inode durably before any namespace bind can cover it.
	fd, err := unix.Open(a.Record.NetnsPath, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	placeholder := os.NewFile(uintptr(fd), a.Record.NetnsPath)
	defer placeholder.Close()
	if err = unix.Fchown(fd, 0, 0); err != nil {
		return err
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Gid != 0 || st.Size != 0 {
		return errors.New("created namespace placeholder has unexpected identity")
	}
	if err = unix.Fchmod(fd, 0600); err != nil {
		return err
	}
	if err = placeholder.Sync(); err != nil {
		return err
	}
	if err = networkSyncNamespaceParent(a.Record.NetnsPath); err != nil {
		return err
	}
	a.Record.NetnsPlaceholderDev = uint64(st.Dev)
	a.Record.NetnsPlaceholderIno = st.Ino
	if err = n.save(ctx, a); err != nil {
		return err
	}
	pin, err := networkNewNamespace(ctx)
	if err != nil {
		return err
	}
	a.namespacePin = pin
	var native unix.Stat_t
	if err = unix.Fstat(int(pin.Fd()), &native); err != nil {
		return err
	}
	kind, err := unix.IoctlRetInt(int(pin.Fd()), unix.NS_GET_NSTYPE)
	if err != nil || kind != unix.CLONE_NEWNET {
		return errors.Join(errors.New("native namespace FD has wrong type"), err)
	}
	a.Record.NetnsDev = uint64(native.Dev)
	a.Record.NetnsIno = native.Ino
	if err = n.save(ctx, a); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = networkHostNamespaces(); err != nil {
		return err
	}
	source := fmt.Sprintf("/proc/self/fd/%d", pin.Fd())
	target := fmt.Sprintf("/proc/self/fd/%d", placeholder.Fd())
	if err = unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	a.namespacePublished = true
	// Prove a persistent bind in both owner and PID1 views, with the exact FD
	// identity saved above. The creating OS thread has already restored its netns.
	return networkObserveNamespace(a)
}
func networkSyncNamespaceParent(path string) error {
	f, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func networkUnmountNamespace(a *networkAllocation) error {
	if err := networkHostNamespaces(); err != nil {
		return err
	}
	var st unix.Stat_t
	err := unix.Lstat(a.Record.NetnsPath, &st)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	var fs unix.Statfs_t
	if err = unix.Statfs(a.Record.NetnsPath, &fs); err != nil {
		return err
	}
	if fs.Type == unix.NSFS_MAGIC {
		// Cleanup does not require successful PID1 publication: a failed prelaunch
		// bind may still be owned in the manager view. It DOES require exact NSFS
		// identity and never lazily detaches a foreign or busy mount.
		if a.Record.NetnsIno == 0 || st.Ino != a.Record.NetnsIno || uint64(st.Dev) != a.Record.NetnsDev {
			return errors.New("refusing to unmount an unowned namespace bind")
		}
		if err = unix.Unmount(a.Record.NetnsPath, 0); err != nil {
			return err
		}
		if err = unix.Lstat(a.Record.NetnsPath, &st); err != nil {
			return err
		}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Gid != 0 || st.Size != 0 || st.Ino != a.Record.NetnsPlaceholderIno || uint64(st.Dev) != a.Record.NetnsPlaceholderDev || a.Record.NetnsPlaceholderIno == 0 {
		return errors.New("refusing to remove an unowned namespace placeholder")
	}
	if err = unix.Unlink(a.Record.NetnsPath); err != nil {
		return err
	}
	return networkSyncNamespaceParent(a.Record.NetnsPath)
}

func (n *Network) movePeerNamespace(ctx context.Context, a *networkAllocation) error {
	if a.namespacePin == nil || a.Record.PeerIfIndex <= 0 {
		return errors.New("owned peer namespace FD/ifindex missing")
	}
	if err := networkHostNamespaces(); err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	var request [unix.NLMSG_HDRLEN + unix.SizeofIfInfomsg + 8]byte
	binary.NativeEndian.PutUint32(request[:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], unix.RTM_NEWLINK)
	binary.NativeEndian.PutUint16(request[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(request[8:12], 1)
	request[unix.NLMSG_HDRLEN] = unix.AF_UNSPEC
	binary.NativeEndian.PutUint32(request[unix.NLMSG_HDRLEN+4:unix.NLMSG_HDRLEN+8], uint32(a.Record.PeerIfIndex))
	attr := request[unix.NLMSG_HDRLEN+unix.SizeofIfInfomsg:]
	binary.NativeEndian.PutUint16(attr[:2], 8)
	binary.NativeEndian.PutUint16(attr[2:4], unix.IFLA_NET_NS_FD)
	binary.NativeEndian.PutUint32(attr[4:8], uint32(a.namespacePin.Fd()))
	if err = unix.Sendto(fd, request[:], 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, n.cfg.OperationTimeout)
	defer cancel()
	var response [4096]byte
	for {
		if err = bounded.Err(); err != nil {
			return err
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err = unix.Poll(poll, 50)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return errors.New("peer move netlink authority lost")
		}
		if poll[0].Revents&unix.POLLIN == 0 {
			continue
		}
		size, _, flags, from, err := unix.Recvmsg(fd, response[:], nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return err
		}
		sender, ok := from.(*unix.SockaddrNetlink)
		if !ok || sender.Pid != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			return errors.New("untrusted or truncated peer move acknowledgment")
		}
		raw := response[:size]
		for len(raw) >= unix.NLMSG_HDRLEN {
			length := int(binary.NativeEndian.Uint32(raw[:4]))
			if length < unix.NLMSG_HDRLEN || length > len(raw) {
				return errors.New("invalid peer move acknowledgment length")
			}
			if binary.NativeEndian.Uint32(raw[8:12]) == 1 && binary.NativeEndian.Uint16(raw[4:6]) == unix.NLMSG_ERROR {
				if length < unix.NLMSG_HDRLEN+4 {
					return errors.New("short peer move acknowledgment")
				}
				code := int32(binary.NativeEndian.Uint32(raw[unix.NLMSG_HDRLEN:]))
				if code == 0 {
					return nil
				}
				if code > 0 {
					return errors.New("invalid peer move errno")
				}
				return unix.Errno(-code)
			}
			next := (length + 3) &^ 3
			if next > len(raw) {
				break
			}
			raw = raw[next:]
		}
	}
}

// A purge reader may inspect an absent approved boot tree. Existing ancestors
// still have to be protected; this function never creates or repairs a path.
func networkOptionalNamespaceDirectory(runRoot string) (bool, error) {
	target := filepath.Join(runRoot, "netns")
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(target, "/"), "/") {
		current = filepath.Join(current, part)
		var st unix.Stat_t
		if err := unix.Lstat(current, &st); err != nil {
			if errors.Is(err, unix.ENOENT) {
				return false, nil
			}
			return false, err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 {
			return false, errors.New("network reconciliation path has an untrusted ancestor")
		}
		if current == target && (st.Gid != 0 || st.Mode&07777 != 0700) {
			return false, errors.New("network reconciliation directory has unexpected ownership or mode")
		}
	}
	return true, nil
}
