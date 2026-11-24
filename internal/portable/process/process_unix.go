//go:build (linux && !android && (amd64 || arm64)) || (darwin && arm64 && !ios)

package process

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const maxLaunchBytes = 1 << 20

type launchRequest struct {
	Path, Dir string
	Args, Env []string
	Extras    int
	HasLock   bool
}

type guardianReport struct {
	Stage string
	Error string
	Exit  *ExitError
}

func start(self string, s Spec) (*Child, error) {
	request := launchRequest{s.Path, s.Dir, s.Args, s.Env, len(s.ExtraFiles), s.OwnerLock != nil}
	raw, err := encodeLaunch(request)
	if err != nil {
		return nil, err
	}
	lifeR, lifeW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer lifeR.Close()
	configR, configW, err := os.Pipe()
	if err != nil {
		lifeW.Close()
		return nil, err
	}
	defer configR.Close()
	defer configW.Close()
	statusR, statusW, err := os.Pipe()
	if err != nil {
		lifeW.Close()
		return nil, err
	}
	defer statusW.Close()
	transferR, transferW, err := newNativeRendezvous()
	if err != nil {
		lifeW.Close()
		statusR.Close()
		return nil, err
	}
	if transferR != nil {
		defer transferR.Close()
		defer transferW.Close()
	}

	guardian := exec.Command(self, GuardianArg)
	guardian.Env = []string{}
	guardian.Stdin, guardian.Stdout, guardian.Stderr = s.Stdin, s.Stdout, s.Stderr
	guardian.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	guardian.ExtraFiles = make([]*os.File, 0, 5+len(s.ExtraFiles))
	guardian.ExtraFiles = append(guardian.ExtraFiles, lifeR, configR, statusW)
	if transferW != nil {
		guardian.ExtraFiles = append(guardian.ExtraFiles, transferW)
	}
	if s.OwnerLock != nil {
		s.OwnerLock.mu.Lock()
		if s.OwnerLock.file == nil {
			s.OwnerLock.mu.Unlock()
			lifeW.Close()
			statusR.Close()
			return nil, errors.New("closed process owner lock")
		}
		guardian.ExtraFiles = append(guardian.ExtraFiles, s.OwnerLock.file)
	}
	guardian.ExtraFiles = append(guardian.ExtraFiles, s.ExtraFiles...)
	err = guardian.Start()
	if s.OwnerLock != nil {
		s.OwnerLock.mu.Unlock()
	}
	if err != nil {
		lifeW.Close()
		statusR.Close()
		return nil, fmt.Errorf("start native lifetime guardian: %w", err)
	}
	lifeR.Close()
	configR.Close()
	statusW.Close()
	if transferW != nil {
		transferW.Close()
	}
	_, writeErr := configW.Write(raw)
	configW.Close()
	decoder := json.NewDecoder(io.LimitReader(statusR, maxLaunchBytes))
	var initial guardianReport
	if err := decoder.Decode(&initial); err != nil || initial.Stage != "started" || writeErr != nil {
		lifeW.Close()
		statusR.Close()
		waitErr := guardian.Wait()
		if err == nil && waitErr == nil && initial.Stage == "refused" && initial.Error != "" {
			return nil, fmt.Errorf("native guardian refused launch: %s", initial.Error)
		}
		return nil, errors.Join(ErrUnobserved, err, writeErr, waitErr, reportError(initial))
	}
	backup, err := receiveNativeBackup(transferR)
	if err != nil {
		lifeW.Close()
		var final guardianReport
		readErr := decoder.Decode(&final)
		statusR.Close()
		waitErr := guardian.Wait()
		if readErr == nil && waitErr == nil && final.Stage == "exited" && final.Error == "" {
			return nil, err // launch failed, but there is positive scope cleanup proof
		}
		return nil, errors.Join(ErrUnobserved, err, readErr, waitErr, reportError(final))
	}

	child := &Child{done: make(chan struct{}), force: func() { lifeW.Close() }}
	go func() {
		defer close(child.done)
		defer closeNativeBackup(backup)
		var report guardianReport
		err := decoder.Decode(&report)
		statusR.Close()
		child.forceOnce.Do(child.force)
		valid := err == nil && report.Stage == "exited" && report.Error == ""
		var stopErr error
		if !valid {
			// A lost status channel already invalidates scope proof. Do not
			// wait for the guardian before stopping through the independent
			// capability. On Darwin, closing lifeW also revokes the sentinel.
			stopErr = stopNativeBackup(backup)
		}
		waitErr := guardian.Wait()
		if !valid || waitErr != nil {
			if valid {
				stopErr = stopNativeBackup(backup)
			}
			child.proof = errors.Join(ErrUnobserved, err, waitErr, reportError(report), stopErr)
			return
		}
		if report.Exit != nil {
			child.exit = report.Exit
		}
	}()
	return child, nil
}

func reportError(report guardianReport) error {
	if report.Error != "" {
		return errors.New(report.Error)
	}
	return nil
}

func encodeLaunch(request launchRequest) ([]byte, error) {
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxLaunchBytes {
		return nil, errors.New("native launch configuration exceeds limit")
	}
	return raw, nil
}

func decodeLaunch(f *os.File) (launchRequest, error) {
	var req launchRequest
	raw, err := io.ReadAll(io.LimitReader(f, maxLaunchBytes+1))
	if err != nil {
		return req, err
	}
	if len(raw) > maxLaunchBytes {
		return req, errors.New("native launch configuration exceeds limit")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&req); err != nil {
		return req, err
	}
	if err = dec.Decode(new(any)); err != io.EOF || req.Extras < 0 || req.Extras > 65535 {
		return req, errors.New("invalid native launch configuration")
	}
	if req.Env == nil {
		req.Env = []string{}
	}
	return req, nil
}

// RunGuardian is the private entry point. It does not read commands or use the
// caller's standard streams for lifetime control or launch status.
func RunGuardian() error {
	if handled, err := runExecStage(); handled {
		return err
	}
	life := os.NewFile(3, "native lifetime reader")
	config := os.NewFile(4, "native launch reader")
	status := os.NewFile(5, "native status writer")
	defer life.Close()
	defer status.Close()
	encoder := json.NewEncoder(status)
	refuse := func(err error) error {
		return encoder.Encode(guardianReport{Stage: "refused", Error: err.Error()})
	}
	req, err := decodeLaunch(config)
	config.Close()
	if err != nil {
		return refuse(err)
	}
	if err = sealInherited(); err != nil {
		return refuse(err)
	}
	first := uintptr(6)
	var transfer *os.File
	if transferNativeHandle {
		transfer = os.NewFile(first, "native identity transfer socket")
		defer transfer.Close()
		first++
	}
	var owner *os.File
	if req.HasLock {
		owner = os.NewFile(first, "installation owner lock")
		defer owner.Close()
		first++
	}
	files := make([]*os.File, 3, 3+req.Extras)
	files[0], files[1], files[2] = os.Stdin, os.Stdout, os.Stderr
	for i := range req.Extras {
		files = append(files, os.NewFile(first+uintptr(i), "native extra file"))
	}
	closeTargetFiles := func() {
		for _, f := range files {
			f.Close()
		}
	}
	// This umask is local to the guardian and native role. Engine socket paths
	// start closed to other users even before GVX changes the mode to 0600.
	unix.Umask(0o077)

	// Install a real SIGCHLD handler before launch, including if the owner ran
	// with SIGCHLD ignored. The guardian is the only waiter of its children.
	changed := make(chan os.Signal, 1)
	signal.Notify(changed, syscall.SIGCHLD)
	defer signal.Stop(changed)
	revoked := make(chan struct{})
	go func() {
		defer close(revoked)
		// The channel carries no commands. EOF (or any invalid input/read error)
		// irrevocably revokes the scope.
		var unexpected [1]byte
		_, _ = life.Read(unexpected[:])
	}()
	select {
	case <-revoked:
		return refuse(errors.New("native lifetime owner already gone"))
	default:
	}
	scope, err := guardianStart(req, files, life, owner)
	closeTargetFiles()
	if err != nil {
		if errors.Is(err, ErrUnobserved) {
			return err
		}
		return refuse(err)
	}
	defer scope.close()
	if err := scope.announce(transfer); err != nil {
		_, cleanupErr := scope.wait(changed, revoked, true)
		if cleanupErr == nil {
			return refuse(err)
		}
		return errors.Join(err, cleanupErr)
	}
	if err := encoder.Encode(guardianReport{Stage: "started"}); err != nil {
		_, cleanupErr := scope.wait(changed, revoked, true)
		return errors.Join(err, cleanupErr)
	}
	exit, err := scope.wait(changed, revoked, false)
	if err != nil {
		return encoder.Encode(guardianReport{Stage: "failed", Error: err.Error()})
	}
	return encoder.Encode(guardianReport{Stage: "exited", Exit: exit})
}

func unixExit(status unix.WaitStatus) *ExitError {
	if status.Signaled() {
		return &ExitError{Code: -1, Signal: int(status.Signal())}
	}
	if status.ExitStatus() != 0 {
		return &ExitError{Code: int64(status.ExitStatus())}
	}
	return nil
}

func sealFDDirectory(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("enumerate inherited native descriptors: %w", err)
	}
	for _, entry := range entries {
		if fd, err := strconv.Atoi(entry.Name()); err == nil && fd > 2 {
			_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC)
			if err != nil && !errors.Is(err, unix.EBADF) {
				return fmt.Errorf("restrict inherited descriptor %d: %w", fd, err)
			}
		}
	}
	return nil
}
