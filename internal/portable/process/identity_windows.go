//go:build windows && (amd64 || arm64)

package process

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// BootIdentity uses the NT kernel boot environment GUID. It does not infer a
// reboot from wall time or PID reuse.
func BootIdentity() (string, error) {
	const systemBootEnvironmentInformation = 90
	var env struct {
		BootIdentifier windows.GUID
		FirmwareType   uint32
		BootFlags      uint64
	}
	var length uint32
	if err := windows.NtQuerySystemInformation(systemBootEnvironmentInformation, unsafe.Pointer(&env), uint32(unsafe.Sizeof(env)), &length); err != nil {
		return "", fmt.Errorf("query Windows boot identity: %w", err)
	}
	if length < uint32(unsafe.Sizeof(env.BootIdentifier)) || env.BootIdentifier == (windows.GUID{}) {
		return "", errors.New("invalid Windows boot identity")
	}
	return env.BootIdentifier.String(), nil
}

// SelfIdentity combines system boot, Windows process creation time and PID.
func SelfIdentity() (string, error) {
	boot, err := BootIdentity()
	if err != nil {
		return "", err
	}
	var started, ended, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &started, &ended, &kernel, &user); err != nil {
		return "", err
	}
	ticks := uint64(started.HighDateTime)<<32 | uint64(started.LowDateTime)
	if ticks == 0 {
		return "", errors.New("invalid Windows process creation identity")
	}
	return fmt.Sprintf("%s/%d/%d", boot, os.Getpid(), ticks), nil
}
