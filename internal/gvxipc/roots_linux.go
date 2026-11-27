//go:build linux

package gvxipc

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"golang.org/x/sys/unix"
)

// openDirectory walks only the approved path, pinning each component and never
// following a symlink, including intermediate components.
func openDirectory(path string) (*os.File, error) {
	return openDirectoryWithFlags(path, unix.O_RDONLY)
}

func openDirectoryWithFlags(path string, flags int) (*os.File, error) {
	if !canonicalAbsolute(path) {
		return nil, errors.New("noncanonical directory")
	}
	fd, e := unix.Open("/", flags|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, flags|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), path), nil
}
func rootAttrs(f *os.File) (gvxcontract.RootAttrs, error) {
	var s unix.Stat_t
	if e := unix.Fstat(int(f.Fd()), &s); e != nil {
		return gvxcontract.RootAttrs{}, e
	}
	if s.Mode&unix.S_IFMT != unix.S_IFDIR || s.Mode&07000 != 0 {
		return gvxcontract.RootAttrs{}, errors.New("root is not a plain directory")
	}
	return gvxcontract.RootAttrs{UID: s.Uid, GID: s.Gid, Mode: s.Mode & 0777}, nil
}
func rootStep(entry gvxcontract.RootInitEntry, attrs gvxcontract.RootAttrs) (int, error) {
	if entry.Disposition == gvxcontract.RootDispositionRetained {
		if attrs != entry.Target {
			return 0, errors.New("retained root mismatch; repair prohibited")
		}
		return 2, nil
	}
	if attrs == entry.Target {
		return 2, nil
	}
	if attrs == entry.Pre {
		return 0, nil
	}
	intermediate := entry.Pre
	intermediate.UID = entry.Target.UID
	intermediate.GID = entry.Target.GID
	if attrs == intermediate {
		return 1, nil
	}
	return 0, errors.New("root does not match a known durable initialization step")
}
func initializeRoots(v gvxcontract.BridgeInit, p gvxcontract.RootInitPayload) (gvxcontract.RootInitResult, []*os.File, error) {
	result := gvxcontract.RootInitResult{Digest: v.Roots.Digest, Nonce: p.Nonce}
	files := make([]*os.File, 0, len(p.Roots))
	fail := func(e error) (gvxcontract.RootInitResult, []*os.File, error) {
		for _, f := range files {
			f.Close()
		}
		return gvxcontract.RootInitResult{}, nil, e
	}
	for _, entry := range p.Roots {
		f, e := openDirectory(entry.Mountpoint)
		if e != nil {
			return fail(e)
		}
		files = append(files, f)
		attrs, e := initializeRoot(f, entry, unix.Fsync)
		if e != nil {
			return fail(e)
		}
		result.Results = append(result.Results, gvxcontract.RootStepResult{RootID: entry.RootID, Step: 2, Observed: attrs})
	}
	return result, files, nil
}

func initializeRoot(f *os.File, entry gvxcontract.RootInitEntry, syncNew func(int) error) (gvxcontract.RootAttrs, error) {
	attrs, err := rootAttrs(f)
	if err != nil {
		return attrs, err
	}
	step, err := rootStep(entry, attrs)
	if err != nil {
		return attrs, err
	}
	if entry.Disposition == gvxcontract.RootDispositionNew {
		if step == 0 {
			if err = unix.Fchown(int(f.Fd()), int(entry.Target.UID), int(entry.Target.GID)); err != nil {
				return attrs, err
			}
		}
		if step < 2 {
			if err = unix.Fchmod(int(f.Fd()), entry.Target.Mode); err != nil {
				return attrs, err
			}
		}
		if syncNew != nil {
			if err = syncNew(int(f.Fd())); err != nil {
				return attrs, err
			}
		}
	}
	attrs, err = rootAttrs(f)
	if err == nil && attrs != entry.Target {
		err = errors.New("root target readback mismatch")
	}
	return attrs, err
}

func allThreads(trap, a, b, c uintptr) error {
	_, _, e := syscall.AllThreadsSyscall(trap, a, b, c)
	if e != 0 {
		return e
	}
	return nil
}
func allThreads6(trap, a, b, c, d, e, f uintptr) error {
	_, _, err := syscall.AllThreadsSyscall6(trap, a, b, c, d, e, f)
	if err != 0 {
		return err
	}
	return nil
}

// This binary is built CGO_ENABLED=0. AllThreadsSyscall changes every runtime
// thread, including future threads; a locked-OS-thread credential workaround is
// deliberately not used. Any unsupported syscall or readback fails closed.
func dropPrivileges(uid, gid uint32) error {
	if uid == 0 || gid == 0 {
		return errors.New("nonroot identity required")
	}
	if e := allThreads(unix.SYS_SETGROUPS, 0, 0, 0); e != nil {
		return e
	}
	for cap := range uintptr(64) {
		e := allThreads6(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, cap, 0, 0, 0, 0)
		if errors.Is(e, unix.EINVAL) && cap >= 41 {
			break
		}
		if e != nil {
			return e
		}
	}
	if e := allThreads6(unix.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0, 0); e != nil {
		return e
	}
	if e := allThreads6(unix.SYS_PRCTL, unix.PR_SET_KEEPCAPS, 0, 0, 0, 0, 0); e != nil {
		return e
	}
	if e := allThreads(unix.SYS_SETRESGID, uintptr(gid), uintptr(gid), uintptr(gid)); e != nil {
		return e
	}
	if e := allThreads(unix.SYS_SETRESUID, uintptr(uid), uintptr(uid), uintptr(uid)); e != nil {
		return e
	}
	h := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	var pinned runtime.Pinner
	pinned.Pin(&h)
	pinned.Pin(&data)
	e := allThreads(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&data[0])), 0)
	runtime.KeepAlive(&h)
	runtime.KeepAlive(&data)
	pinned.Unpin()
	if e != nil {
		return e
	}
	if e = allThreads6(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); e != nil {
		return e
	}
	return verifyThreads(uid, gid)
}
func verifyThreads(uid, gid uint32) error {
	entries, e := os.ReadDir("/proc/self/task")
	if e != nil {
		return e
	}
	if len(entries) == 0 {
		return errors.New("no task credential evidence")
	}
	for _, entry := range entries {
		if _, e = strconv.ParseUint(entry.Name(), 10, 32); e != nil {
			return e
		}
		f, e := os.Open(filepath.Join("/proc/self/task", entry.Name(), "status"))
		if e != nil {
			return e
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 4096), 16384)
		seen := map[string]bool{}
		for scanner.Scan() {
			key, value, ok := strings.Cut(scanner.Text(), ":")
			if !ok {
				continue
			}
			fields := strings.Fields(value)
			switch key {
			case "Uid", "Gid":
				want := uid
				if key == "Gid" {
					want = gid
				}
				if len(fields) != 4 {
					f.Close()
					return errors.New("invalid task credentials")
				}
				for _, s := range fields {
					n, e := strconv.ParseUint(s, 10, 32)
					if e != nil || uint32(n) != want {
						f.Close()
						return errors.New("task retained root credentials")
					}
				}
				seen[key] = true
			case "Groups":
				if len(fields) != 0 {
					f.Close()
					return errors.New("task retained supplementary groups")
				}
				seen[key] = true
			case "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb":
				if len(fields) != 1 {
					f.Close()
					return errors.New("missing capability evidence")
				}
				n, e := strconv.ParseUint(fields[0], 16, 64)
				if e != nil || n != 0 {
					f.Close()
					return errors.New("task retained capabilities")
				}
				seen[key] = true
			case "NoNewPrivs":
				if len(fields) != 1 || fields[0] != "1" {
					f.Close()
					return errors.New("task can acquire privileges")
				}
				seen[key] = true
			}
		}
		e = scanner.Err()
		f.Close()
		if e != nil {
			return e
		}
		if len(seen) != 9 {
			return fmt.Errorf("incomplete task privilege evidence: %d", len(seen))
		}
	}
	return nil
}
