//go:build darwin && arm64 && !ios

package process

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const darwinSentinelFD = "_CHATANIUM_PORTABLE_DARWIN_SENTINEL_FD"

// There is no signal-capable process descriptor on Darwin. The separately
// armed sentinel is the actual native process's parent and sole waiter. It
// never needs to turn a reported PID into a signal capability. This pair of
// EOF channels has different writers: loss of either the supervisor or its
// primary guardian revokes the scope even while the other process survives.
const transferNativeHandle = false

func newNativeRendezvous() (*os.File, *os.File, error) { return nil, nil, nil }
func receiveNativeBackup(*os.File) (int, error)        { return -1, nil }
func closeNativeBackup(int)                            {}
func stopNativeBackup(int) error                       { return nil }

type nativeScope struct {
	p       *os.Process
	revoker *os.File
	status  *os.File
	decoder *json.Decoder
}

// On Darwin the independent termination capability has already been armed by
// guardianStart and acknowledged by the sentinel. No child FD is transferred.
func (s *nativeScope) announce(*os.File) error { return nil }

func (s *nativeScope) wait(_ <-chan os.Signal, _ <-chan struct{}, force bool) (*ExitError, error) {
	if force {
		s.revoker.Close()
	}
	var final guardianReport
	err := s.decoder.Decode(&final)
	s.revoker.Close()
	_, waitErr := s.p.Wait()
	if err != nil || waitErr != nil || final.Stage != "exited" || final.Error != "" {
		err := errors.Join(errors.New("Darwin sentinel did not prove native exit"), err, waitErr, reportError(final))
		return nil, revokeDarwinGroup(err)
	}
	return final.Exit, nil
}

func (s *nativeScope) close() {
	s.revoker.Close()
	s.status.Close()
	_ = s.p.Release()
}

// The primary guardian itself pins this private group for the entire call.
// Never send a signal to a group ID read from a message or durable record.
// This emergency path includes the guardian and is not proof of native exit.
func revokeDarwinGroup(cause error) error {
	if unix.Getpgrp() != os.Getpid() {
		return errors.Join(ErrUnobserved, cause, errors.New("Darwin guardian no longer owns its private process group"))
	}
	return errors.Join(ErrUnobserved, cause, unix.Kill(0, unix.SIGKILL))
}

func guardianStart(req launchRequest, files []*os.File, supervisorLife, owner *os.File) (*nativeScope, error) {
	if os.Getuid() == 0 || os.Geteuid() == 0 || os.Getuid() != os.Geteuid() {
		return nil, errors.New("Darwin descendant prevention requires an unprivileged real and effective UID")
	}
	if unix.Getpgrp() != os.Getpid() {
		return nil, errors.New("Darwin guardian does not own a private process group")
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
	defer statusW.Close()
	guardianLife, revoker, err := os.Pipe()
	if err != nil {
		statusR.Close()
		return nil, err
	}
	defer guardianLife.Close()
	first := len(files)
	forward := append(files, configR, statusW, guardianLife, supervisorLife)
	if owner != nil {
		forward = append(forward, owner)
	}
	p, err := os.StartProcess(self, []string{self, GuardianArg}, &os.ProcAttr{
		Env: []string{darwinSentinelFD + "=" + strconv.Itoa(first)}, Files: forward,
	})
	if err != nil {
		revoker.Close()
		statusR.Close()
		return nil, fmt.Errorf("start independent Darwin lifetime sentinel: %w", err)
	}
	configR.Close()
	statusW.Close()
	guardianLife.Close()
	_, writeErr := configW.Write(raw)
	configW.Close()
	decoder := json.NewDecoder(io.LimitReader(statusR, maxLaunchBytes))
	var initial guardianReport
	readErr := decoder.Decode(&initial)
	if readErr != nil || initial.Stage != "started" || writeErr != nil {
		revoker.Close()
		statusR.Close()
		_, waitErr := p.Wait()
		if readErr == nil && waitErr == nil && initial.Stage == "refused" && initial.Error != "" {
			return nil, fmt.Errorf("Darwin sentinel refused launch: %s", initial.Error)
		}
		return nil, revokeDarwinGroup(errors.Join(readErr, waitErr, writeErr, reportError(initial)))
	}
	return &nativeScope{p: p, revoker: revoker, status: statusR, decoder: decoder}, nil
}

func runExecStage() (bool, error) {
	position, ok := os.LookupEnv(darwinSentinelFD)
	if !ok {
		return runDarwinExec()
	}
	first, err := strconv.Atoi(position)
	if err != nil || first < 3 || first > 65538 {
		return true, errors.New("invalid Darwin sentinel descriptors")
	}
	return true, runDarwinSentinel(first)
}

func runDarwinSentinel(first int) error {
	config := os.NewFile(uintptr(first), "Darwin sentinel launch reader")
	status := os.NewFile(uintptr(first+1), "Darwin sentinel status writer")
	guardian := os.NewFile(uintptr(first+2), "Darwin guardian lifetime reader")
	supervisor := os.NewFile(uintptr(first+3), "Darwin supervisor lifetime reader")
	defer status.Close()
	defer guardian.Close()
	defer supervisor.Close()
	encoder := json.NewEncoder(status)
	refuse := func(err error) error {
		return encoder.Encode(guardianReport{Stage: "refused", Error: err.Error()})
	}
	req, err := decodeLaunch(config)
	config.Close()
	if err != nil {
		return refuse(err)
	}
	if req.Extras+3 != first {
		return refuse(errors.New("Darwin sentinel descriptor layout disagrees with request"))
	}
	if err := sealInherited(); err != nil {
		return refuse(err)
	}
	if req.HasLock {
		owner := os.NewFile(uintptr(first+4), "Darwin sentinel installation owner lock")
		defer owner.Close()
	}

	changed := make(chan os.Signal, 1)
	signal.Notify(changed, syscall.SIGCHLD)
	defer signal.Stop(changed)
	revoked := make(chan struct{})
	var revoke sync.Once
	watch := func(channel *os.File) {
		var unexpected [1]byte
		_, _ = channel.Read(unexpected[:])
		revoke.Do(func() { close(revoked) })
	}
	go watch(guardian)
	go watch(supervisor)
	select {
	case <-revoked:
		return refuse(errors.New("Darwin native lifetime owner already gone"))
	default:
	}

	files := make([]*os.File, 3, first)
	files[0], files[1], files[2] = os.Stdin, os.Stdout, os.Stderr
	for fd := 3; fd < first; fd++ {
		files = append(files, os.NewFile(uintptr(fd), "Darwin sentinel extra file"))
	}
	p, err := darwinStartTarget(req, files)
	for _, file := range files {
		file.Close()
	}
	if err != nil {
		if errors.Is(err, ErrUnobserved) {
			return err
		}
		return refuse(err)
	}
	defer p.Release()
	if err := encoder.Encode(guardianReport{Stage: "started"}); err != nil {
		_, cleanupErr := guardianWait(p.Pid, changed, revoked, true)
		return errors.Join(err, cleanupErr)
	}
	exit, err := guardianWait(p.Pid, changed, revoked, false)
	if err != nil {
		return encoder.Encode(guardianReport{Stage: "failed", Error: err.Error()})
	}
	return encoder.Encode(guardianReport{Stage: "exited", Exit: exit})
}
