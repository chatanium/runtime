//go:build linux

package bootstrap

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thirdscam/chatanium/internal/legacy/host"
	"golang.org/x/sys/unix"
)

// terminalNativeContext keeps native placement and ownership outside receipt
// authority. Production obtains it only from the canonical exclusive host guard;
// an isolated native fixture owns its protected root and actual flock instead.
type terminalNativeContext struct {
	root           *os.File
	rootPath       string
	controlPath    string
	receiptPath    string
	ownerUID       uint32
	installationID RuntimeInstallationID
	guard          *host.ManagementGuard
	lock           *os.File
	rootIdentity   terminalNativeIdentity
	lockIdentity   terminalNativeIdentity
}

func terminalNativeFromGuard(guard *host.ManagementGuard, id RuntimeInstallationID) (*terminalNativeContext, error) {
	if guard == nil || guard.Mode() != host.ManagementExclusive {
		return nil, host.ErrManagementGuardRequired
	}
	fd, err := guard.RootFD()
	if err != nil {
		return nil, err
	}
	duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	native, err := newTerminalNativeContext(os.NewFile(uintptr(duplicate), terminalRoot), terminalRoot, id, 0)
	if err != nil {
		return nil, err
	}
	native.guard = guard
	if err = native.validate(); err != nil {
		native.Close()
		return nil, err
	}
	return native, nil
}

// acquireTerminalNativeAt is an internal native fixture boundary, not a public
// root/UID override. Its authority comes from a private current-user-owned root,
// a fully published permanent marker, and a held exclusive native flock.
func acquireTerminalNativeAt(ctx context.Context, rootPath string, id RuntimeInstallationID) (*terminalNativeContext, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Open(rootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	root := os.NewFile(uintptr(fd), rootPath)
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		root.Close()
		return nil, err
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Mode&07777 != 0700 {
		root.Close()
		return nil, errors.New("terminal native fixture requires a private current-user-owned root")
	}
	native, err := newTerminalNativeContext(root, rootPath, id, stat.Uid)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*terminalNativeContext, error) {
		native.Close()
		return nil, err
	}
	lockName := ".management.lock"
	lockPath := filepath.Join(rootPath, lockName)
	if _, err = os.Lstat(lockPath); os.IsNotExist(err) {
		file, _, createErr := terminalAnonymous(root)
		if createErr != nil {
			return fail(createErr)
		}
		createErr = terminalWriteAnonymous(file, []byte(host.ManagementMarker))
		if createErr == nil {
			createErr = terminalLink(root, file, lockName)
		}
		closeErr := file.Close()
		if createErr != nil {
			return fail(createErr)
		}
		if closeErr != nil {
			return fail(closeErr)
		}
		if err = root.Sync(); err != nil {
			return fail(err)
		}
	} else if err != nil {
		return fail(err)
	}
	lockFD, err := unix.Openat(fd, lockName, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(err)
	}
	native.lock = os.NewFile(uintptr(lockFD), lockPath)
	for {
		err = unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return fail(err)
		}
		select {
		case <-ctx.Done():
			return fail(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if err = native.validate(); err != nil {
		return fail(err)
	}
	return native, nil
}

func newTerminalNativeContext(root *os.File, rootPath string, id RuntimeInstallationID, ownerUID uint32) (*terminalNativeContext, error) {
	fail := func(err error) (*terminalNativeContext, error) {
		root.Close()
		return nil, err
	}
	if !validID(string(id)) || !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath || rootPath == "/" || strings.ContainsRune(rootPath, 0) {
		return fail(errors.New("invalid terminal native placement"))
	}
	native := &terminalNativeContext{
		root: root, rootPath: rootPath, ownerUID: ownerUID, installationID: id,
		controlPath: filepath.Join(rootPath, "installations", string(id), "control"),
		receiptPath: filepath.Join(rootPath, ".purge-terminal-"+string(id)+".json"),
	}
	var err error
	native.rootIdentity, err = terminalObserve(rootPath)
	if err != nil {
		return fail(err)
	}
	if native.rootIdentity.Absent || native.rootIdentity.Kind != "directory" || native.rootIdentity.UID != ownerUID || native.rootIdentity.Mode&0022 != 0 {
		return fail(errors.New("unsafe terminal native root"))
	}
	var stat unix.Stat_t
	if err = unix.Fstat(int(root.Fd()), &stat); err != nil {
		return fail(err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(stat.Dev) != native.rootIdentity.Device || stat.Ino != native.rootIdentity.Inode || stat.Uid != ownerUID {
		return fail(errors.New("terminal native root descriptor differs from its path"))
	}
	return native, nil
}

func (native *terminalNativeContext) validate() error {
	if native == nil || native.root == nil || native.guard == nil && native.lock == nil {
		return host.ErrManagementGuardRequired
	}
	if native.guard != nil && (native.rootPath != terminalRoot || native.ownerUID != 0 || native.guard.Mode() != host.ManagementExclusive) {
		return host.ErrManagementGuardRequired
	}
	actual, err := terminalObserve(native.rootPath)
	if err != nil {
		return err
	}
	expected := native.rootIdentity
	// Selected ancestor removal changes directory link counts, not root identity.
	actual.Links, expected.Links = 0, 0
	if actual != expected {
		return errors.New("terminal native root changed")
	}
	var stat unix.Stat_t
	if err = unix.Fstat(int(native.root.Fd()), &stat); err != nil {
		return err
	}
	if uint64(stat.Dev) != expected.Device || stat.Ino != expected.Inode || stat.Uid != native.ownerUID {
		return errors.New("terminal native root descriptor changed")
	}
	fd, err := unix.Openat(int(native.root.Fd()), ".management.lock", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "terminal-management-marker")
	defer file.Close()
	if err = unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 || stat.Uid != native.ownerUID || stat.Nlink != 1 || stat.Size != int64(len(host.ManagementMarker)) {
		return errors.New("unsafe terminal native management marker")
	}
	marker, err := io.ReadAll(io.LimitReader(file, int64(len(host.ManagementMarker))+1))
	if err != nil {
		return err
	}
	if string(marker) != host.ManagementMarker {
		return errors.New("terminal native management marker differs")
	}
	identity, err := terminalObserve(filepath.Join(native.rootPath, ".management.lock"))
	if err != nil {
		return err
	}
	if identity.Device != uint64(stat.Dev) || identity.Inode != stat.Ino {
		return errors.New("terminal native management marker replaced while opening")
	}
	if native.lockIdentity.Path != "" && identity != native.lockIdentity {
		return errors.New("terminal native management marker changed")
	}
	if native.lock != nil {
		var held unix.Stat_t
		if err = unix.Fstat(int(native.lock.Fd()), &held); err != nil {
			return err
		}
		if held.Ino != stat.Ino || held.Dev != stat.Dev {
			return errors.New("terminal native flock inode differs")
		}
	}
	native.lockIdentity = identity
	return nil
}

func (native *terminalNativeContext) Close() error {
	if native == nil {
		return nil
	}
	var err error
	if native.lock != nil {
		err = errors.Join(unix.Flock(int(native.lock.Fd()), unix.LOCK_UN), native.lock.Close())
		native.lock = nil
	}
	if native.root != nil {
		err = errors.Join(err, native.root.Close())
		native.root = nil
	}
	return err
}
