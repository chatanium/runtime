//go:build linux && !android && (amd64 || arm64)

package process

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// BootIdentity is the Linux kernel boot UUID, not a wall clock estimate.
func BootIdentity() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(raw))
	if len(id) != 36 {
		return "", errors.New("invalid Linux boot identity")
	}
	return id, nil
}

// SelfIdentity is the process birth identity within the current kernel boot
// and PID namespace. It is for durable ownership records, not signal delivery.
func SelfIdentity() (string, error) {
	boot, err := BootIdentity()
	if err != nil {
		return "", err
	}
	namespace, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return "", err
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return "", errors.New("missing Linux process creation time")
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) <= 19 {
		return "", errors.New("missing Linux process creation time")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64) // proc stat field 22
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%s/%d/%d", boot, namespace, os.Getpid(), start), nil
}

func socketPeerUID(fd int) (uint32, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return cred.Uid, nil
}

// An access ACL on Linux cannot grant named users/group rights outside the
// group-class mode mask, which is already checked for private files and dirs.
func privateACL(int) error { return nil }
