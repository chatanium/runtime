//go:build linux

package gvxstage

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// preparationFilter is a closed x86-64 policy, not a caller-supplied program.
// Syscall numbers are intentionally ABI constants, not the build host's SYS_*.
func preparationFilter() [15]unix.SockFilter {
	return [15]unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: unix.AUDIT_ARCH_X86_64},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, Jf: 1, K: 0x40000000},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 7, K: 46},  // sendmsg
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 6, K: 47},  // recvmsg
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 5, K: 299}, // recvmmsg
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 4, K: 307}, // sendmmsg
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 3, K: 425}, // io_uring_setup
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 2, K: 426}, // io_uring_enter
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: 427}, // io_uring_register
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	}
}

// PreparationFilterDigest hashes the exact eight-byte Linux sock_filter
// instructions installed on x86-64 (little-endian code, jt, jf, k), in order.
func PreparationFilterDigest() string {
	filter := preparationFilter()
	var canonical [len(filter) * 8]byte
	for i, instruction := range filter {
		p := canonical[i*8 : (i+1)*8]
		binary.LittleEndian.PutUint16(p, instruction.Code)
		p[2], p[3] = instruction.Jt, instruction.Jf
		binary.LittleEndian.PutUint32(p[4:], instruction.K)
	}
	digest := sha256.Sum256(canonical[:])
	return "sha256:" + hex.EncodeToString(digest[:])
}

func preparationTSYNCResult(result uintptr, errno syscall.Errno) error {
	if errno != 0 {
		return fmt.Errorf("preparation TSYNC: %w", errno)
	}
	// A positive TID is a synchronization failure even with errno == 0.
	if result != 0 {
		return errors.New("preparation TSYNC did not synchronize every thread")
	}
	return nil
}

func installPreparationFilter() error {
	if runtime.GOARCH != "amd64" {
		return errors.New("preparation writer filter requires x86-64")
	}
	if e := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); e != nil {
		return e
	}
	filter := preparationFilter()
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	result, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(filter)
	return preparationTSYNCResult(result, errno)
}

func confinePreparation() error {
	if e := installPreparationFilter(); e != nil {
		return e
	}
	return preparationDescriptorHygiene()
}

func preparationDescriptorHygiene() error {
	// Only stdin/stdout/stderr survive exec. Mark, do not close: Go's live
	// epoll/eventfd and connected gate must remain usable through FILTER_READY
	// and START. The verified executable is also CLOEXEC, and exec resolves its
	// pinned /proc/self/fd path before closing it. Atomic close_range avoids a
	// racy /proc/self/fd walk; runtime-created descriptors are already CLOEXEC.
	if e := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); e != nil {
		return fmt.Errorf("preparation descriptor CLOEXEC: %w", e)
	}
	for fd := range 3 {
		var st unix.Stat_t
		if e := unix.Fstat(fd, &st); e != nil {
			return e
		}
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			return errors.New("preparation standard descriptor is a directory")
		}
	}
	return nil
}
