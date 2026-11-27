package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// Exercise the actual go-plugin listener after authenticated INIT/START. The
// established bridge/core-v2 connection must still deliver STOP after this race.
func ipcComponentProbe(ctx context.Context, p *probeSession) error {
	dir, err := guestIPCDirectory()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var path string
	for _, entry := range entries {
		if entry.Type()&os.ModeSocket != 0 {
			if path != "" {
				return errors.New("ambiguous guest primary socket")
			}
			path = filepath.Join(dir, entry.Name())
		}
	}
	if path == "" {
		return errors.New("guest primary socket unavailable")
	}
	dirfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)
	fd, err := unix.Openat(dirfd, filepath.Base(path), unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var original unix.Stat_t
	if err = unix.Fstat(fd, &original); err != nil || original.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		original.Uid != uint32(os.Getuid()) || original.Gid != uint32(os.Getgid()) || original.Mode&07777 != 0660 {
		return errors.New("guest primary pin identity mismatch")
	}
	p.record("ipc-component", "pin-opened", nil, map[string]any{
		"opath": true, "pid": os.Getpid(), "device": uint64(original.Dev), "inode": original.Ino})
	outsidePath := filepath.Join(p.scratch, "endpoint-replacement")
	outside, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: outsidePath})
	if err != nil {
		return err
	}
	defer outside.Close()
	if err = os.Rename(path, path+".retained"); err != nil {
		return err
	}
	if err = os.Symlink(outsidePath, path); err != nil {
		return err
	}
	replaced, err := os.Lstat(path)
	if err != nil || replaced.Mode()&os.ModeSymlink == 0 {
		return errors.New("ordered socket replacement not observed")
	}
	p.record("ipc-component", "pathname-replaced", nil, map[string]any{"replacement_symlink": true})
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return err
	}
	defer conn.Close()
	raw, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		return err
	}
	var peer *unix.Ucred
	var peerErr error
	if err = raw.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || peerErr != nil {
		return errors.New("retained socket peer unavailable")
	}
	p.record("ipc-component", "retained-connect", nil, map[string]any{"peer_pid": peer.Pid, "peer_uid": peer.Uid, "peer_gid": peer.Gid})
	if int(peer.Pid) != os.Getpid() {
		return errors.New("retained socket connected replacement")
	}
	fresh, err := unix.Openat(dirfd, filepath.Base(path), unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	var changed unix.Stat_t
	err = unix.Fstat(fresh, &changed)
	unix.Close(fresh)
	if err != nil {
		return err
	}
	p.record("ipc-component", "fresh-path-inspection", nil, map[string]any{"is_symlink": changed.Mode&unix.S_IFMT == unix.S_IFLNK})
	if changed.Mode&unix.S_IFMT != unix.S_IFLNK {
		return errors.New("replacement was not rejected by confined inspection")
	}
	if err = outside.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		return err
	}
	unexpected, acceptErr := outside.AcceptUnix()
	if unexpected != nil {
		unexpected.Close()
	}
	p.record("ipc-component", "replacement-connect", acceptErr, map[string]any{"outside_accepted": unexpected != nil})
	if unexpected != nil {
		return errors.New("replacement listener unexpectedly reached")
	}
	if timeout, ok := acceptErr.(net.Error); !ok || !timeout.Timeout() {
		return errors.New("replacement listener observation incomplete")
	}
	p.record("ipc-component", "returned-not-policy-proof", nil, nil)
	return nil
}
