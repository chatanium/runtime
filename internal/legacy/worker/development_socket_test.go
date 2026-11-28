//go:build linux

package worker

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDevelopmentSocketIsPrivateAndAuthenticatesPeerUID(t *testing.T) {
	path, config := developmentTestPaths(t)
	socket, err := listenDevelopmentSocket(path, config.Host.StorageRoot, config.Host.IPCRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		t.Fatal("development socket is not a private 0600 Unix socket")
	}
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer, err := socket.listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if !developmentSameUser(peer, uint32(os.Geteuid())) || developmentSameUser(peer, uint32(os.Geteuid())+1) {
		t.Fatal("SO_PEERCRED authentication did not enforce the exact effective UID")
	}
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned socket inode was not cleaned")
	}
}

func TestDevelopmentSocketRejectsExistingTargetsWithoutClobbering(t *testing.T) {
	for _, kind := range []string{"regular", "symlink", "socket"} {
		t.Run(kind, func(t *testing.T) {
			path, config := developmentTestPaths(t)
			switch kind {
			case "regular":
				if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(filepath.Dir(path), "missing"), path); err != nil {
					t.Fatal(err)
				}
			case "socket":
				listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if socket, err := listenDevelopmentSocket(path, config.Host.StorageRoot, config.Host.IPCRoot); err == nil {
				socket.Close()
				t.Fatal("existing socket target was accepted")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("existing socket target was replaced or removed")
			}
		})
	}
}

func TestDevelopmentSocketRejectsUnsafeDirectories(t *testing.T) {
	for _, kind := range []string{"mode", "parent symlink", "ancestor symlink", "storage", "ipc", "relative", "owner"} {
		t.Run(kind, func(t *testing.T) {
			path, config := developmentTestPaths(t)
			switch kind {
			case "mode":
				if err := os.Chmod(filepath.Dir(path), 0750); err != nil {
					t.Fatal(err)
				}
			case "parent symlink":
				alias := filepath.Join(filepath.Dir(filepath.Dir(path)), "alias")
				if err := os.Symlink(filepath.Dir(path), alias); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(alias, "control.sock")
			case "ancestor symlink":
				root := filepath.Dir(filepath.Dir(path))
				alias := root + "-alias"
				if err := os.Symlink(root, alias); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Remove(alias) })
				path = filepath.Join(alias, "control", "control.sock")
			case "storage":
				path = filepath.Join(config.Host.StorageRoot, "control.sock")
			case "ipc":
				path = filepath.Join(config.Host.IPCRoot, "control.sock")
			case "relative":
				path = "control.sock"
			case "owner":
				if os.Geteuid() != 0 {
					t.Skip("changing directory ownership requires root")
				}
				if err := os.Chown(filepath.Dir(path), 1, 1); err != nil {
					t.Fatal(err)
				}
			}
			if socket, err := listenDevelopmentSocket(path, config.Host.StorageRoot, config.Host.IPCRoot); err == nil {
				socket.Close()
				t.Fatal("unsafe development socket directory was accepted")
			}
		})
	}
}

func TestDevelopmentSocketCleanupPreservesReplacementInode(t *testing.T) {
	for _, kind := range []string{"regular", "socket", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			path, config := developmentTestPaths(t)
			socket, err := listenDevelopmentSocket(path, config.Host.StorageRoot, config.Host.IPCRoot)
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "regular":
				if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("missing", path); err != nil {
					t.Fatal(err)
				}
			case "socket":
				replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				defer replacement.Close()
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := socket.Close(); err != nil {
				t.Fatal(err)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("cleanup removed another owner's replacement inode")
			}
		})
	}
}

func TestDevelopmentSocketCleanupUsesPinnedParent(t *testing.T) {
	path, config := developmentTestPaths(t)
	socket, err := listenDevelopmentSocket(path, config.Host.StorageRoot, config.Host.IPCRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	parent := filepath.Dir(path)
	moved := parent + "-moved"
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(moved, filepath.Base(path))); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("socket in pinned parent was not cleaned")
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "replacement" {
		t.Fatal("cleanup followed renamed parent to another inode")
	}
}

func TestDevelopmentListenerBoundsConcurrentConnections(t *testing.T) {
	path, config := developmentTestPaths(t)
	socket, err := listenDevelopmentSocket(path, config.Host.StorageRoot, config.Host.IPCRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	var accepted []net.Conn
	defer func() {
		for _, connection := range accepted {
			connection.Close()
		}
	}()
	for range developmentMaxConnections {
		client, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		connection, err := socket.listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		accepted = append(accepted, connection)
	}
	extra, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	result := make(chan net.Conn, 1)
	go func() {
		connection, _ := socket.listener.Accept()
		result <- connection
	}()
	extra.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection limit did not reject excess client")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("excess connection remained admitted until timeout")
	}
	accepted[0].Close()
	replacement, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	select {
	case connection := <-result:
		if connection == nil {
			t.Fatal("listener failed after releasing a connection slot")
		}
		accepted = append(accepted, connection)
	case <-time.After(time.Second):
		t.Fatal("closed connection did not release admission capacity")
	}
}
