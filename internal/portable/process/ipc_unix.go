//go:build (linux && !android && (amd64 || arm64)) || (darwin && arm64 && !ios)

package process

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const directoryOpen = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW

// OwnerIdentity identifies the effective Unix owner required by management IPC.
func OwnerIdentity() (string, error) { return "uid:" + strconv.Itoa(os.Geteuid()), nil }

// CheckPrivateFileACL checks an already opened descriptor. The caller still
// owns verification of the intended file type, parent and path binding.
func CheckPrivateFileACL(file *os.File) error {
	var st unix.Stat_t
	fd := int(file.Fd())
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0o077 != 0 {
		return errors.New("private native descriptor has other owners or permissions")
	}
	err := privateACL(fd)
	runtime.KeepAlive(file)
	return err
}

// EnsurePrivateDir creates one owner-only leaf, or verifies an existing one.
// It never creates ancestors or follows links.
func EnsurePrivateDir(path string) error {
	if !endpointPath(path) {
		return errors.New("absolute, clean private directory required")
	}
	parent, err := walkDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	if err := unix.Mkdirat(parent, filepath.Base(path), 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return &os.PathError{Op: "mkdir private directory", Path: path, Err: err}
	}
	return CheckPrivateDir(path)
}

// ProtectPrivateDir verifies the Unix mode/owner of a newly created directory.
func ProtectPrivateDir(path string) error { return CheckPrivateDir(path) }

// CheckPrivateDir verifies the directory and its safe, link-free path.
func CheckPrivateDir(path string) error {
	fd, err := openPrivateDir(path)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func endpointPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Dir(path) != path && launchString(path)
}

func walkDirectory(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !launchString(path) {
		return -1, errors.New("absolute, clean native directory required")
	}
	fd, err := unix.Open("/", directoryOpen, 0)
	if err != nil {
		return -1, err
	}
	for component := range strings.SplitSeq(strings.TrimPrefix(path, "/"), "/") {
		if component == "" {
			continue
		}
		if err := checkDirectoryOwner(fd, false); err != nil {
			unix.Close(fd)
			return -1, &os.PathError{Op: "verify native directory ancestor", Path: path, Err: err}
		}
		next, err := unix.Openat(fd, component, directoryOpen, 0)
		unix.Close(fd)
		if err != nil {
			return -1, &os.PathError{Op: "open native directory", Path: path, Err: err}
		}
		fd = next
	}
	if err := checkDirectoryOwner(fd, false); err != nil {
		unix.Close(fd)
		return -1, &os.PathError{Op: "verify native directory", Path: path, Err: err}
	}
	return fd, nil
}

func checkDirectoryOwner(fd int, private bool) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	uid := uint32(os.Geteuid())
	if private {
		if st.Uid != uid || st.Mode&0o7777 != 0o700 {
			return errors.New("private native directory must belong to this UID with mode 0700")
		}
	} else if (st.Uid != uid && st.Uid != 0) || st.Mode&0o022 != 0 && st.Mode&unix.S_ISVTX == 0 {
		return errors.New("native directory ancestor can be replaced by an untrusted UID")
	}
	return privateACL(fd)
}

func openPrivateDir(path string) (int, error) {
	if !endpointPath(path) {
		return -1, errors.New("absolute, clean private directory required")
	}
	fd, err := walkDirectory(path)
	if err != nil {
		return -1, err
	}
	if err := checkDirectoryOwner(fd, true); err != nil {
		unix.Close(fd)
		return -1, &os.PathError{Op: "verify private native directory", Path: path, Err: err}
	}
	return fd, nil
}

// Listen binds owner-only local management IPC. It never unlinks an existing
// path to gain ownership; the caller must coordinate recovery with its lock.
func Listen(path string) (net.Listener, error) {
	if !endpointPath(path) {
		return nil, errors.New("absolute, clean native socket path required")
	}
	if err := CheckPrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return &ownerListener{ln}, nil
}

type ownerListener struct{ *net.UnixListener }

func (l *ownerListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		if err = verifyPeer(conn); err == nil {
			return conn, nil
		}
		conn.Close()
	}
}

// Dial connects only to a private management endpoint for this effective UID.
func Dial(ctx context.Context, path string) (net.Conn, error) {
	return DialEngine(ctx, path)
}

// DialEngine verifies a GVX Unix path and its connected peer. This does not
// implement the GVX protocol or authorize an application-level command.
func DialEngine(ctx context.Context, path string) (net.Conn, error) {
	if !endpointPath(path) {
		return nil, errors.New("absolute, clean native socket path required")
	}
	fd, err := openPrivateDir(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstatat(fd, filepath.Base(path), &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, &os.PathError{Op: "inspect native socket", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("native socket must be local and owner-matched")
	}
	switch st.Mode & 0o7777 {
	case 0o700: // GVX binds under the managed umask before chmod(0600).
		return nil, ErrEndpointNotReady
	case 0o600:
	default:
		return nil, errors.New("native socket must have mode 0600")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	if err := verifyPeer(conn.(*net.UnixConn)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func verifyPeer(c *net.UnixConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		var uid uint32
		uid, peerErr = socketPeerUID(int(fd))
		if peerErr == nil && uid != uint32(os.Geteuid()) {
			peerErr = errors.New("native socket peer has a different UID")
		}
	}); err != nil {
		return err
	}
	return peerErr
}

// ReadEngineToken returns the exact verified hexadecimal token, not its path
// or a credential read through a symlink or other special file.
func ReadEngineToken(path string) ([]byte, error) {
	f, err := openPrivateFile(path, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readToken(f)
}

// Lock takes a nonblocking exclusive lock on a persistent private file.
func Lock(path string) (*OwnerLock, error) {
	f, err := openPrivateFile(path, unix.O_CREAT|unix.O_RDWR)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrOwnerBusy
		}
		return nil, fmt.Errorf("lock portable installation ownership: %w", err)
	}
	return &OwnerLock{file: f}, nil
}

func openPrivateFile(path string, flags int) (*os.File, error) {
	if !endpointPath(path) {
		return nil, errors.New("absolute, clean native file path required")
	}
	parent, err := openPrivateDir(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, filepath.Base(path), flags|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, &os.PathError{Op: "open private native file", Path: path, Err: err}
	}
	var st unix.Stat_t
	err = unix.Fstat(fd, &st)
	if err == nil && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o7777 != 0o600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1) {
		err = errors.New("private native file must be a singly linked regular owner file with mode 0600")
	}
	if err == nil {
		err = privateACL(fd)
	}
	if err != nil {
		unix.Close(fd)
		return nil, &os.PathError{Op: "verify private native file", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}
