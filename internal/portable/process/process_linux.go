//go:build linux && !android && (amd64 || arm64)

package process

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const transferNativeHandle = true

type nativeScope struct {
	p     *os.Process
	pidfd int
}

func (s *nativeScope) announce(socket *os.File) error {
	defer socket.Close()
	message := [1]byte{'P'}
	// The connected socketpair is inherited only by the trusted guardian.
	// rights carries the descriptor acquired at creation, not a reported PID.
	n, err := unix.SendmsgN(int(socket.Fd()), message[:], unix.UnixRights(s.pidfd), nil, unix.MSG_NOSIGNAL)
	if err != nil || n != len(message) {
		return errors.Join(errors.New("transfer native pidfd to supervisor"), err)
	}
	return nil
}

func (s *nativeScope) wait(changed <-chan os.Signal, revoked <-chan struct{}, force bool) (*ExitError, error) {
	return guardianWait(s.p.Pid, changed, revoked, force)
}

func (s *nativeScope) close() {
	unix.Close(s.pidfd)
	_ = s.p.Release()
	runtime.UnlockOSThread()
}

func newNativeRendezvous() (*os.File, *os.File, error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("create native identity transfer socket: %w", err)
	}
	return os.NewFile(uintptr(pair[0]), "supervisor native identity channel"), os.NewFile(uintptr(pair[1]), "guardian native identity channel"), nil
}

func receiveNativeBackup(socket *os.File) (int, error) {
	var message [1]byte
	var ancillary [64]byte
	n, used, flags, _, err := unix.Recvmsg(int(socket.Fd()), message[:], ancillary[:], unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		return -1, fmt.Errorf("receive native pidfd: %w", err)
	}
	msgs, err := unix.ParseSocketControlMessage(ancillary[:used])
	var fds []int
	for i := range msgs {
		rights, rightsErr := unix.ParseUnixRights(&msgs[i])
		fds = append(fds, rights...)
		err = errors.Join(err, rightsErr)
	}
	valid := n == 1 && message[0] == 'P' && flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) == 0 && len(msgs) == 1 && len(fds) == 1
	if valid && err == nil {
		err = unix.PidfdSendSignal(fds[0], 0, nil, 0)
		if err == nil || errors.Is(err, unix.ESRCH) {
			return fds[0], nil // live pidfd, or the original identity already exited
		}
	}
	for _, fd := range fds {
		unix.Close(fd)
	}
	return -1, errors.Join(errors.New("invalid original child pidfd handoff"), err)
}

func closeNativeBackup(fd int) {
	if fd >= 0 {
		unix.Close(fd)
	}
}

func stopNativeBackup(fd int) error {
	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("terminate original Linux executable after guardian loss: %w", err)
	}
	// This transitively observes only the original executable. The caller
	// must never take this as evidence that escaped descendants are gone.
	poll := [...]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	deadline := time.Now().Add(3 * time.Second)
	for {
		ms := time.Until(deadline).Milliseconds()
		if ms < 1 {
			return errors.New("original Linux executable exit not observed after guardian loss")
		}
		_, err := unix.Poll(poll[:], int(ms))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("wait for original Linux executable pidfd: %w", err)
		}
		if poll[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
			return nil
		}
	}
}

func sealInherited() error        { return sealFDDirectory("/proc/self/fd") }
func runExecStage() (bool, error) { return false, nil }

func guardianStart(req launchRequest, files []*os.File, _, _ *os.File) (*nativeScope, error) {
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return nil, fmt.Errorf("enable native descendant reaping: %w", err)
	}
	self, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return nil, fmt.Errorf("require native pidfd ownership: %w", err)
	}
	err = unix.PidfdSendSignal(self, 0, nil, 0)
	if err == nil {
		// Our own pidfd is valid but can never be waited on as a child.
		err = ownedPIDFD(self)
		if errors.Is(err, unix.ECHILD) {
			err = nil
		} else if err == nil {
			err = errors.New("self unexpectedly waitable as a child")
		}
	}
	unix.Close(self)
	if err != nil {
		return nil, fmt.Errorf("require pidfd signal and wait ownership: %w", err)
	}
	if procPID, err := os.Readlink("/proc/self"); err != nil || procPID != strconv.Itoa(os.Getpid()) {
		return nil, errors.Join(errors.New("native lifetime guardian requires procfs for its own PID namespace"), err)
	}
	if _, err := os.ReadFile("/proc/thread-self/children"); err != nil {
		return nil, fmt.Errorf("require procfs native child enumeration: %w", err)
	}
	file, err := os.Stat(req.Path)
	if err != nil {
		return nil, err
	}
	if !file.Mode().IsRegular() || file.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return nil, errors.New("managed Linux native role must be a regular non-set-ID executable")
	}
	_, err = unix.Getxattr(req.Path, "security.capability", nil)
	switch {
	case err == nil:
		return nil, errors.New("managed Linux native role must not have a file capabilities attribute")
	case !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP):
		return nil, fmt.Errorf("verify absence of Linux native role file capabilities: %w", err)
	}
	// PR_SET_PDEATHSIG follows the creating thread, not just the process.
	// Keep this OS thread alive through scope cleanup.
	runtime.LockOSThread()
	pidfd := -1
	p, err := os.StartProcess(req.Path, append([]string{req.Path}, req.Args...), &os.ProcAttr{
		Dir: req.Dir, Env: req.Env, Files: files,
		Sys: &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL, PidFD: &pidfd},
	})
	if err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}
	if pidfd < 0 {
		// Under clone policies that disallow CLONE_PIDFD, this is still our
		// original unreaped direct child; the sole waiter has not started.
		pidfd, err = unix.PidfdOpen(p.Pid, 0)
	}
	if err == nil {
		err = ownedPIDFD(pidfd)
	}
	if err != nil {
		// At this point no process has reaped p, so the original Go Process
		// object cannot signal a reused identity even if pidfd creation failed.
		_ = p.Kill()
		_, cleanupErr := guardianWait(p.Pid, nil, nil, true)
		closeNativeBackup(pidfd)
		_ = p.Release()
		runtime.UnlockOSThread()
		err = fmt.Errorf("require signalable original Linux child pidfd: %w", err)
		if cleanupErr != nil {
			err = errors.Join(ErrUnobserved, err, cleanupErr)
		}
		return nil, err
	}
	return &nativeScope{p: p, pidfd: pidfd}, nil
}

func guardianWait(root int, changed <-chan os.Signal, revoked <-chan struct{}, force bool) (*ExitError, error) {
	var exit *ExitError
	rootReaped := false
	for {
		var status unix.WaitStatus
		pid, err := unix.Wait4(-1, &status, unix.WNOHANG|unix.WALL, nil)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.ECHILD):
			// The kernel reparents orphaned descendants to this subreaper before
			// removing their ancestor. No children means there are no writers left.
			if !rootReaped {
				return nil, errors.New("native child was not reaped by its guardian")
			}
			return exit, nil
		case err != nil:
			return nil, fmt.Errorf("reap native process scope: %w", err)
		case pid > 0:
			if pid == root && !rootReaped && (status.Exited() || status.Signaled()) {
				rootReaped = true
				exit = unixExit(status)
				force = true
			}
			continue
		}
		if force {
			killNativeChildren()
			// Retry enumeration until wait(2) proves the scope empty. An exiting
			// task may still be in an uninterruptible syscall; keep the lock and
			// do not report cleanup. Reparenting may expose more children.
			timer := time.NewTimer(20 * time.Millisecond)
			select {
			case <-changed:
				timer.Stop()
			case <-timer.C:
			}
		} else {
			select {
			case <-revoked:
				force = true
			case <-changed:
			}
		}
	}
}

func killNativeChildren() {
	threads, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return
	}
	for _, thread := range threads {
		raw, err := os.ReadFile("/proc/self/task/" + thread.Name() + "/children")
		if err != nil {
			continue
		}
		for _, field := range strings.Fields(string(raw)) {
			pid, err := strconv.Atoi(field)
			if err != nil || pid <= 0 {
				continue
			}
			// The sole guardian waiter has not reaped this listed child. Still
			// ask the kernel to attest the newly acquired handle is waitable
			// as our child before sending a signal; never trust procfs alone.
			fd, err := unix.PidfdOpen(pid, 0)
			if err != nil {
				continue
			}
			if ownedPIDFD(fd) == nil {
				_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
			}
			unix.Close(fd)
		}
	}
}

func ownedPIDFD(fd int) error {
	var state unix.Siginfo
	return unix.Waitid(unix.P_PIDFD, fd, &state, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT|unix.WALL, nil)
}
