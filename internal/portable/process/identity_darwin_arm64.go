//go:build darwin && arm64 && !ios

package process

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// BootIdentity is the kernel boot session UUID. The wall clock and boottime
// timestamp can change while the same processes remain alive.
func BootIdentity() (string, error) {
	id, err := unix.Sysctl("kern.bootsessionuuid")
	if err != nil {
		return "", err
	}
	if len(id) != 36 {
		return "", errors.New("invalid Darwin boot session identity")
	}
	return id, nil
}

// SelfIdentity uses the kernel's process start time, not the current time.
func SelfIdentity() (string, error) {
	boot, err := BootIdentity()
	if err != nil {
		return "", err
	}
	pid := os.Getpid()
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return "", err
	}
	started := info.Proc.P_starttime
	if int(info.Proc.P_pid) != pid || started.Sec <= 0 {
		return "", errors.New("invalid Darwin process creation identity")
	}
	return fmt.Sprintf("%s/%d/%d.%06d", boot, pid, started.Sec, started.Usec), nil
}

func socketPeerUID(fd int) (uint32, error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return cred.Uid, nil
}

// Darwin extended ACLs can grant beyond the POSIX mode. Query the pinned
// vnode's ATTR_CMN_EXTENDED_SECURITY and reject every non-deny ACE. This also
// permits usual home directories with an explicit everyone-deny-delete ACE.
func privateACL(fd int) error {
	const (
		refSize       = 12 // total length + attrreference_t
		fileSecHeader = 44 // magic, two GUIDs, entry count and flags
		aceSize       = 24 // GUID, flags and rights
		entryLimit    = 128
	)
	var raw [refSize + fileSecHeader + entryLimit*aceSize]byte
	attr := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: unix.ATTR_CMN_EXTENDED_SECURITY}
	_, _, errno := darwinACLCall(darwinAttrListAddr(), uintptr(fd), uintptr(unsafe.Pointer(&attr)), uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)), 0, 0)
	if errno != 0 {
		return fmt.Errorf("read Darwin native directory ACL: %w", errno)
	}
	u32 := binary.LittleEndian.Uint32
	total := int(u32(raw[0:4]))
	start := 4 + int(int32(u32(raw[4:8]))) // attr_dataoffset is relative to the reference
	size := int(u32(raw[8:12]))
	if total < refSize || total > len(raw) || start < refSize || start > total || size > total-start {
		return errors.New("invalid Darwin native ACL extent")
	}
	if size == 0 {
		return nil
	}
	acl := raw[start : start+size]
	if size < fileSecHeader || u32(acl[0:4]) != 0x012cc16d { // KAUTH_FILESEC_MAGIC
		return errors.New("invalid Darwin native ACL header")
	}
	entries := int(u32(acl[36:40]))
	if entries == int(^uint32(0)) && size == fileSecHeader { // KAUTH_FILESEC_NOACL
		return nil
	}
	if entries > entryLimit || size != fileSecHeader+entries*aceSize {
		return errors.New("invalid Darwin native ACL entries")
	}
	for i := range entries {
		flags := u32(acl[fileSecHeader+i*aceSize+16:])
		if flags&0xf != 2 { // KAUTH_ACE_KINDMASK and KAUTH_ACE_DENY
			return errors.New("Darwin native path ACL grants access outside its POSIX mode")
		}
	}
	return nil
}

//go:linkname darwinACLCall syscall.syscall6
func darwinACLCall(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

func darwinAttrListAddr() uintptr

//go:cgo_import_dynamic libc_portable_fgetattrlist fgetattrlist "/usr/lib/libSystem.B.dylib"
