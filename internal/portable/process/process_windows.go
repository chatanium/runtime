//go:build windows && (amd64 || arm64)

package process

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Introduced in Windows 10. Unlike create-suspended-then-assign, the job list
// is applied by process creation itself; owner death cannot leave an unowned
// suspended process in the interval before AssignProcessToJobObject.
const procThreadAttributeJobList = 0x0002000d

func RunGuardian() error { return errors.New("native guardian entry point is Unix-only") }

func start(_ string, s Spec) (*Child, error) {
	if s.OwnerLock != nil {
		s.OwnerLock.mu.Lock()
		defer s.OwnerLock.mu.Unlock()
		if s.OwnerLock.file == nil {
			return nil, errors.New("closed process owner lock")
		}
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create native lifetime job: %w", err)
	}
	keepJob := false
	defer func() {
		if !keepJob {
			windows.CloseHandle(job)
		}
	}()
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return nil, fmt.Errorf("require no-breakaway kill-on-close job: %w", err)
	}
	attr, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return nil, err
	}
	defer attr.Delete()
	if err = attr.Update(procThreadAttributeJobList, unsafe.Pointer(&job), unsafe.Sizeof(job)); err != nil {
		return nil, fmt.Errorf("require atomic native Job ownership: %w", err)
	}

	handles := make([]windows.Handle, 3+len(s.ExtraFiles))
	defer func() {
		for _, h := range handles {
			if h != 0 {
				windows.CloseHandle(h)
			}
		}
	}()
	current := windows.CurrentProcess()
	for i := range handles {
		var f *os.File
		switch i {
		case 0:
			f = s.Stdin
		case 1:
			f = s.Stdout
		case 2:
			f = s.Stderr
		default:
			f = s.ExtraFiles[i-3]
		}
		null := f == nil
		if null {
			mode := os.O_WRONLY
			if i == 0 {
				mode = os.O_RDONLY
			}
			f, err = os.OpenFile(os.DevNull, mode, 0)
			if err != nil {
				return nil, err
			}
		}
		err = windows.DuplicateHandle(current, windows.Handle(f.Fd()), current, &handles[i], 0, true, windows.DUPLICATE_SAME_ACCESS)
		runtime.KeepAlive(f)
		if null {
			f.Close()
		}
		if err != nil {
			return nil, fmt.Errorf("duplicate explicit native channel %d: %w", i, err)
		}
	}
	if err = attr.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return nil, err
	}
	path, err := windows.UTF16PtrFromString(s.Path)
	if err != nil {
		return nil, err
	}
	line, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{s.Path}, s.Args...)))
	if err != nil {
		return nil, err
	}
	var dir *uint16
	if s.Dir != "" {
		dir, err = windows.UTF16PtrFromString(s.Dir)
		if err != nil {
			return nil, err
		}
	}
	stopEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("create native lifetime stop event: %w", err)
	}
	defer func() {
		if !keepJob {
			windows.CloseHandle(stopEvent)
		}
	}()
	env := windowsEnvironment(s, handles[3:])
	startup := windows.StartupInfoEx{ProcThreadAttributeList: attr.List()}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Flags = windows.STARTF_USESTDHANDLES
	startup.StdInput, startup.StdOutput, startup.StdErr = handles[0], handles[1], handles[2]
	var p windows.ProcessInformation
	flags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW)
	if err := windows.CreateProcess(path, line, nil, nil, true, flags, &env[0], dir, &startup.StartupInfo, &p); err != nil {
		return nil, fmt.Errorf("create native process inside lifetime Job: %w", err)
	}
	defer windows.CloseHandle(p.Thread)

	active, verifyErr := jobActive(job)
	if verifyErr == nil && active != 1 {
		verifyErr = fmt.Errorf("native managed Job has %d members before resume, want one", active)
	}
	if verifyErr == nil {
		var previous uint32
		previous, verifyErr = windows.ResumeThread(p.Thread)
		if verifyErr == nil && previous != 1 {
			verifyErr = fmt.Errorf("unexpected native thread suspend count %d", previous)
		}
	}
	if verifyErr != nil {
		// A process was created. Use its original kernel handle in addition to
		// the job; a launch error is conclusive only once cleanup is observed.
		_ = windows.TerminateProcess(p.Process, 1)
		_, observeErr := observeJob(job, p.Process, 0, true)
		windows.CloseHandle(p.Process)
		return nil, errors.Join(fmt.Errorf("verify and resume native Job member: %w", verifyErr), observeErr)
	}
	var stopMu sync.Mutex
	child := &Child{done: make(chan struct{}), force: func() {
		stopMu.Lock()
		defer stopMu.Unlock()
		if stopEvent != 0 {
			if err := windows.SetEvent(stopEvent); err != nil {
				_ = windows.TerminateJobObject(job, 1)
			}
		}
	}}
	keepJob = true
	go func() {
		defer close(child.done)
		defer windows.CloseHandle(job)
		defer windows.CloseHandle(p.Process)
		child.exit, child.proof = observeJob(job, p.Process, stopEvent, false)
		stopMu.Lock()
		windows.CloseHandle(stopEvent)
		stopEvent = 0
		stopMu.Unlock()
	}()
	return child, nil
}

func windowsEnvironment(s Spec, extras []windows.Handle) []uint16 {
	type entry struct{ name, text string }
	entries := make([]entry, 0, len(s.Env)+len(extras))
	estimatedUnits := 1 // final NUL after the last entry
	for _, item := range s.Env {
		name, _, _ := strings.Cut(item, "=")
		entries = append(entries, entry{strings.ToUpper(name), item})
		estimatedUnits += len(item) + 1
	}
	for i, handle := range extras {
		name := s.ExtraFileEnv[i]
		item := name + "=" + strconv.FormatUint(uint64(handle), 10)
		entries = append(entries, entry{strings.ToUpper(name), item})
		estimatedUnits += len(item) + 1
	}
	slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(a.name, b.name) })
	block := make([]uint16, 0, max(2, estimatedUnits))
	for _, item := range entries {
		for _, r := range item.text {
			block = utf16.AppendRune(block, r)
		}
		block = append(block, 0)
	}
	if len(block) == 0 {
		block = append(block, 0)
	}
	return append(block, 0)
}

func jobActive(job windows.Handle) (uint32, error) {
	// JOBOBJECT_BASIC_ACCOUNTING_INFORMATION.
	var info struct {
		UserTime, KernelTime, PeriodUserTime, PeriodKernelTime                    int64
		TotalPageFault, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses uint32
	}
	err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil)
	return info.ActiveProcesses, err
}

func observeJob(job, main, stop windows.Handle, terminate bool) (error, error) {
	if !terminate {
		status, err := windows.WaitForMultipleObjects([]windows.Handle{main, stop}, false, windows.INFINITE)
		if err != nil {
			return nil, errors.Join(ErrUnobserved, fmt.Errorf("wait for native Job or stop event: %w", err))
		}
		switch status {
		case windows.WAIT_OBJECT_0:
			// The main process handle is already signaled.
		case windows.WAIT_OBJECT_0 + 1:
			terminate = true
		default:
			return nil, errors.Join(ErrUnobserved, fmt.Errorf("unexpected native Job wait result %#x", status))
		}
	}
	killJob := func() error {
		if err := windows.TerminateJobObject(job, 1); err != nil {
			return errors.Join(ErrUnobserved, fmt.Errorf("terminate native lifetime Job: %w", err))
		}
		return nil
	}
	if terminate {
		if err := killJob(); err != nil {
			return nil, err
		}
		status, err := windows.WaitForSingleObject(main, windows.INFINITE)
		if err != nil {
			return nil, errors.Join(ErrUnobserved, fmt.Errorf("wait for owned native process handle: %w", err))
		}
		if status != windows.WAIT_OBJECT_0 {
			return nil, errors.Join(ErrUnobserved, fmt.Errorf("unexpected native process wait result %#x", status))
		}
	}
	for {
		active, err := jobActive(job)
		if err != nil {
			return nil, errors.Join(ErrUnobserved, fmt.Errorf("observe native Job membership: %w", err))
		}
		if active == 0 {
			break
		}
		if !terminate {
			if err := killJob(); err != nil {
				return nil, err
			}
			terminate = true
		}
		time.Sleep(20 * time.Millisecond)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(main, &code); err != nil {
		return fmt.Errorf("get managed native process exit code: %w", err), nil
	}
	if code != 0 {
		return &ExitError{Code: int64(code)}, nil
	}
	return nil, nil
}
