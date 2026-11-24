//go:build darwin && arm64 && !ios

package process

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

const darwinExecFD = "_CHATANIUM_PORTABLE_DARWIN_EXEC_FD"

func sealInherited() error { return sealFDDirectory("/dev/fd") }

// XNU applies the calling non-root process's hard RLIMIT_NPROC to both fork
// and posix_spawn; exec in place is still possible. The supported Darwin
// native roles (HVF engine and worker) run without host subprocesses.
func darwinStartTarget(req launchRequest, files []*os.File) (*os.Process, error) {
	if os.Getuid() == 0 || os.Geteuid() == 0 || os.Getuid() != os.Geteuid() {
		return nil, errors.New("Darwin descendant prevention requires an unprivileged real and effective UID")
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	raw, err := encodeLaunch(req)
	if err != nil {
		return nil, err
	}
	configR, configW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer configR.Close()
	defer configW.Close()
	statusR, statusW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer statusR.Close()
	defer statusW.Close()
	first := len(files)
	p, err := os.StartProcess(self, []string{self, GuardianArg}, &os.ProcAttr{
		Dir: req.Dir, Env: []string{darwinExecFD + "=" + strconv.Itoa(first)},
		Files: append(files, configR, statusW),
	})
	if err != nil {
		return nil, err
	}
	configR.Close()
	statusW.Close()
	_, writeErr := configW.Write(raw)
	configW.Close()
	status, readErr := io.ReadAll(io.LimitReader(statusR, maxLaunchBytes))
	if writeErr != nil || readErr != nil || len(status) != 1 || status[0] != 1 {
		_, cleanupErr := guardianWait(p.Pid, nil, nil, true)
		p.Release()
		if cleanupErr != nil {
			return nil, errors.Join(ErrUnobserved, cleanupErr, writeErr, readErr)
		}
		return nil, errors.Join(fmt.Errorf("Darwin native execution did not establish descendant prevention: %q", status), writeErr, readErr)
	}
	return p, nil
}

func runDarwinExec() (bool, error) {
	position, ok := os.LookupEnv(darwinExecFD)
	if !ok {
		return false, nil
	}
	first, err := strconv.Atoi(position)
	if err != nil || first < 3 || first > 65538 {
		return true, errors.New("invalid Darwin execution descriptors")
	}
	config := os.NewFile(uintptr(first), "Darwin launch reader")
	status := os.NewFile(uintptr(first+1), "Darwin exec result writer")
	defer status.Close()
	if _, err := unix.FcntlInt(status.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		config.Close()
		return true, err
	}
	report := func(err error) (bool, error) {
		_, writeErr := io.WriteString(status, err.Error())
		return true, writeErr
	}
	req, err := decodeLaunch(config)
	config.Close()
	if err != nil {
		return report(err)
	}
	if req.Extras+3 != first || os.Getuid() == 0 || os.Geteuid() == 0 || os.Getuid() != os.Geteuid() {
		return report(errors.New("invalid Darwin native role identity or launch descriptors"))
	}
	file, err := os.Stat(req.Path)
	if err != nil {
		return report(err)
	}
	if !file.Mode().IsRegular() || file.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return report(errors.New("Darwin native role must be a regular, non-set-ID executable"))
	}
	if err := unix.Setrlimit(unix.RLIMIT_NPROC, &unix.Rlimit{}); err != nil {
		return report(fmt.Errorf("deny Darwin native subprocess creation: %w", err))
	}
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NPROC, &limit); err != nil || limit.Cur != 0 || limit.Max != 0 {
		return report(errors.Join(errors.New("Darwin native subprocess limit not active"), err))
	}
	if _, err := status.Write([]byte{1}); err != nil {
		return true, err
	}
	return report(unix.Exec(req.Path, append([]string{req.Path}, req.Args...), req.Env))
}

func guardianWait(root int, changed <-chan os.Signal, revoked <-chan struct{}, force bool) (*ExitError, error) {
	for {
		if force {
			// This is the guardian's direct, unreaped child, and this goroutine
			// is the only waiter. The kernel cannot reuse its identity here.
			if err := unix.Kill(root, unix.SIGKILL); err != nil && !errors.Is(err, unix.ESRCH) {
				return nil, fmt.Errorf("terminate owned Darwin native process: %w", err)
			}
		}
		var status unix.WaitStatus
		var options int
		if !force {
			options = unix.WNOHANG
		}
		pid, err := unix.Wait4(root, &status, options, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reap owned Darwin native process: %w", err)
		}
		if pid == root && (status.Exited() || status.Signaled()) {
			return unixExit(status), nil
		}
		if !force {
			select {
			case <-revoked:
				force = true
			case <-changed:
			}
		}
	}
}
