package app

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

const developmentMaxConnections = 16

type developmentSocket struct {
	listener *developmentListener
	parent   *os.File
	name     string
	device   uint64
	inode    uint64
	once     sync.Once
	err      error
}

func listenDevelopmentSocket(path string, mounts ...string) (*developmentSocket, error) {
	if !canonicalPath(path) || !isolatedHostDirectory(filepath.Dir(path), mounts...) {
		return nil, errors.New("development socket must be private and outside module mounts")
	}
	parentFD, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(path), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, errors.New("development socket parent cannot be opened without symlinks")
	}
	parent := os.NewFile(uintptr(parentFD), "development-socket-parent")
	var parentStat unix.Stat_t
	if unix.Fstat(parentFD, &parentStat) != nil || parentStat.Mode&unix.S_IFMT != unix.S_IFDIR || parentStat.Mode&07777 != 0700 || parentStat.Uid != uint32(os.Geteuid()) {
		parent.Close()
		return nil, errors.New("development socket requires a private effective-user-owned 0700 parent")
	}
	name := filepath.Base(path)
	var existing unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &existing, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		parent.Close()
		return nil, errors.New("development socket path already exists or is inaccessible")
	}
	// Pin the directory during bind/chmod/cleanup rather than re-resolving a
	// mutable path. The public canonical path addresses the same socket inode.
	pinnedPath := "/proc/self/fd/" + strconv.Itoa(parentFD) + "/" + name
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: pinnedPath, Net: "unix"})
	if err != nil {
		parent.Close()
		return nil, errors.New("development socket creation failed")
	}
	listener.SetUnlinkOnClose(false)
	socket := &developmentSocket{listener: &developmentListener{UnixListener: listener, slots: make(chan struct{}, developmentMaxConnections)}, parent: parent, name: name}
	var created unix.Stat_t
	if unix.Fstatat(parentFD, name, &created, unix.AT_SYMLINK_NOFOLLOW) != nil || created.Mode&unix.S_IFMT != unix.S_IFSOCK || created.Uid != uint32(os.Geteuid()) {
		listener.Close()
		parent.Close()
		return nil, errors.New("development socket identity verification failed")
	}
	socket.device, socket.inode = uint64(created.Dev), created.Ino
	// O_PATH avoids following a substituted symlink, while chmod through its
	// descriptor targets the pinned socket inode rather than a replacement.
	socketFD, err := unix.Openat(parentFD, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == nil {
		var opened unix.Stat_t
		if unix.Fstat(socketFD, &opened) != nil || uint64(opened.Dev) != socket.device || opened.Ino != socket.inode {
			err = errors.New("socket replaced")
		} else {
			err = os.Chmod("/proc/self/fd/"+strconv.Itoa(socketFD), 0600)
		}
		unix.Close(socketFD)
	}
	var ready unix.Stat_t
	if err != nil || unix.Fstatat(parentFD, name, &ready, unix.AT_SYMLINK_NOFOLLOW) != nil || uint64(ready.Dev) != socket.device || ready.Ino != socket.inode || ready.Mode&07777 != 0600 {
		socket.Close()
		return nil, errors.New("development socket permissions could not be secured")
	}
	return socket, nil
}

func (socket *developmentSocket) Close() error {
	socket.once.Do(func() {
		_ = socket.listener.Close()
		var current unix.Stat_t
		fd := int(socket.parent.Fd())
		err := unix.Fstatat(fd, socket.name, &current, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil && uint64(current.Dev) == socket.device && current.Ino == socket.inode && current.Mode&unix.S_IFMT == unix.S_IFSOCK {
			if unix.Unlinkat(fd, socket.name, 0) != nil {
				socket.err = errors.New("development socket cleanup failed")
			}
		} else if err != nil && !errors.Is(err, unix.ENOENT) {
			socket.err = errors.New("development socket cleanup failed")
		}
		if socket.parent.Close() != nil {
			socket.err = errors.New("development socket cleanup failed")
		}
	})
	return socket.err
}

type developmentListener struct {
	*net.UnixListener
	slots chan struct{}
}

func (listener *developmentListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			return nil, err
		}
		if !developmentSameUser(connection, uint32(os.Geteuid())) {
			connection.Close()
			continue
		}
		select {
		case listener.slots <- struct{}{}:
			return &developmentConnection{Conn: connection, slots: listener.slots}, nil
		default:
			connection.Close()
		}
	}
}

func developmentSameUser(connection *net.UnixConn, expected uint32) bool {
	raw, err := connection.SyscallConn()
	if err != nil {
		return false
	}
	var peer *unix.Ucred
	var credentialErr error
	if raw.Control(func(fd uintptr) {
		peer, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}) != nil || credentialErr != nil || peer == nil {
		return false
	}
	return peer.Uid == expected
}

type developmentConnection struct {
	net.Conn
	slots chan struct{}
	once  sync.Once
	err   error
}

func (connection *developmentConnection) Close() error {
	connection.once.Do(func() {
		connection.err = connection.Conn.Close()
		<-connection.slots
	})
	return connection.err
}
