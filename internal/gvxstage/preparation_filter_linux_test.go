//go:build linux

package gvxstage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func evaluatePreparationFilter(t *testing.T, arch, number uint32) uint32 {
	t.Helper()
	filter := preparationFilter()
	var accumulator uint32
	for pc := 0; pc < len(filter); pc++ {
		instruction := filter[pc]
		switch instruction.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			switch instruction.K {
			case 0:
				accumulator = number
			case 4:
				accumulator = arch
			default:
				t.Fatal("unexpected seccomp_data offset")
			}
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if accumulator == instruction.K {
				pc += int(instruction.Jt)
			} else {
				pc += int(instruction.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			if accumulator&instruction.K != 0 {
				pc += int(instruction.Jt)
			} else {
				pc += int(instruction.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return instruction.K
		default:
			t.Fatalf("unexpected instruction %#x", instruction.Code)
		}
	}
	t.Fatal("filter fell through")
	return 0
}

func TestPreparationFilterPolicy(t *testing.T) {
	for _, number := range []uint32{46, 47, 299, 307, 425, 426, 427} {
		if got := evaluatePreparationFilter(t, unix.AUDIT_ARCH_X86_64, number); got != unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM) {
			t.Fatalf("ancillary/uring syscall %d action %#x", number, got)
		}
	}
	for _, number := range []uint32{0, 1, 19, 20, 41, 42, 43, 44, 45, 49, 50, 56, 59, 202, 232, 233, 281, 288, 291} {
		if got := evaluatePreparationFilter(t, unix.AUDIT_ARCH_X86_64, number); got != unix.SECCOMP_RET_ALLOW {
			t.Fatalf("ordinary syscall %d action %#x", number, got)
		}
	}
	for _, arch := range []uint32{unix.AUDIT_ARCH_I386, unix.AUDIT_ARCH_AARCH64, 0} {
		if got := evaluatePreparationFilter(t, arch, 1); got != unix.SECCOMP_RET_KILL_PROCESS {
			t.Fatalf("foreign arch %#x action %#x", arch, got)
		}
	}
	if got := evaluatePreparationFilter(t, unix.AUDIT_ARCH_X86_64, 0x40000001); got != unix.SECCOMP_RET_KILL_PROCESS {
		t.Fatalf("x32 action %#x", got)
	}
	filter := preparationFilter()
	actual := unsafe.Slice((*byte)(unsafe.Pointer(&filter[0])), len(filter)*8)
	if runtime.GOARCH == "amd64" {
		digest := sha256.Sum256(actual)
		if got := PreparationFilterDigest(); got != "sha256:"+hex.EncodeToString(digest[:]) {
			t.Fatalf("digest does not bind actual installed instruction bytes: %s", got)
		}
	}
	for _, result := range []uintptr{1, 12345, ^uintptr(0)} {
		if err := preparationTSYNCResult(result, 0); err == nil {
			t.Fatalf("positive/nonzero TSYNC result %d accepted", result)
		}
	}
	if err := preparationTSYNCResult(0, unix.EACCES); !errors.Is(err, unix.EACCES) {
		t.Fatalf("TSYNC error lost: %v", err)
	}
	if err := preparationTSYNCResult(0, 0); err != nil {
		t.Fatal(err)
	}
}

func preparationChild(t *testing.T, mode string, files ...*os.File) ([]byte, error) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestPreparationFilterChild$")
	command.Env = append(os.Environ(), "GVX_PREPARATION_TEST_CHILD="+mode)
	command.ExtraFiles = files
	return command.CombinedOutput()
}

func TestPreparationFilterIsolated(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("fixed writer ABI is x86-64")
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	left := os.NewFile(uintptr(pair[0]), "left")
	right := os.NewFile(uintptr(pair[1]), "right")
	defer left.Close()
	defer right.Close()
	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	output, err := preparationChild(t, "filter", left, right, directory)
	if err != nil || string(output) != "exec-clean\n" {
		t.Fatalf("isolated filter/exec: %v\n%s", err, output)
	}
	for _, mode := range []string{"filter-failure", "ack-failure"} {
		output, err := preparationChild(t, mode)
		if err != nil || len(output) != 0 {
			t.Fatalf("%s reached target or failed unexpectedly: %v\n%s", mode, err, output)
		}
	}
	output, err = preparationChild(t, "x32")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGSYS {
		t.Fatalf("x32 not killed by fixed policy: %v\n%s", err, output)
	}
}

func TestPreparationFilterChild(t *testing.T) {
	mode := os.Getenv("GVX_PREPARATION_TEST_CHILD")
	if mode == "" {
		return
	}
	if mode == "target" {
		fmt.Println("TARGET-EXECUTED")
		os.Exit(0)
	}
	if mode == "postexec" {
		// Numeric descriptor slots may be reused by the new Go runtime. Compare
		// the inherited directory identity instead of assuming slots stay empty.
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			fd, err := strconv.Atoi(entry.Name())
			if err != nil {
				t.Fatal(err)
			}
			var st unix.Stat_t
			if unix.Fstat(fd, &st) == nil && fmt.Sprintf("%d:%d", st.Dev, st.Ino) == os.Getenv("GVX_PREPARATION_TEST_INODE") {
				t.Fatal("inherited data directory survived exec")
			}
		}
		fmt.Println("exec-clean")
		os.Exit(0)
	}
	if mode == "filter-failure" || mode == "ack-failure" {
		c := testPreparationConfig(t)
		var input bytes.Buffer
		if err := WritePreparationMessage(&input, preparationMessage(c, PreparationArm)); err != nil {
			t.Fatal(err)
		}
		stream := struct {
			io.Reader
			io.Writer
		}{&input, io.Discard}
		err := exchangePreparation(stream, c, func() error {
			if mode == "filter-failure" {
				return preparationTSYNCResult(12345, 0)
			}
			return confinePreparation()
		})
		if err != nil {
			os.Exit(0)
		}
		execPreparationTestChild(t, "target", "")
	}
	if mode == "x32" {
		if err := installPreparationFilter(); err != nil {
			t.Fatal(err)
		}
		unix.RawSyscall(0x40000000|1, 1, 0, 0)
		t.Fatal("x32 syscall survived")
	}
	if mode != "filter" {
		t.Fatalf("unknown child mode %q", mode)
	}
	// Verify SCM_RIGHTS was usable before installation, so an outer sandbox's
	// existing policy cannot make this assertion vacuously pass.
	if _, err := unix.SendmsgN(3, []byte("b"), unix.UnixRights(5), nil, 0); err != nil {
		t.Fatalf("baseline SCM_RIGHTS: %v", err)
	}
	data, ancillary := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	_, n, _, _, err := unix.Recvmsg(4, data, ancillary, 0)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := unix.ParseSocketControlMessage(ancillary[:n])
	if err != nil || len(messages) != 1 {
		t.Fatalf("baseline ancillary: %+v %v", messages, err)
	}
	rights, err := unix.ParseUnixRights(&messages[0])
	if err != nil || len(rights) != 1 {
		t.Fatalf("baseline rights: %v %v", rights, err)
	}
	unix.Close(rights[0])
	// Queue a second actual rights transfer while the sender is unrestricted.
	// Receiving the already-queued descriptor must still fail after TSYNC.
	if _, err := unix.SendmsgN(3, []byte("q"), unix.UnixRights(5), nil, 0); err != nil {
		t.Fatalf("queued SCM_RIGHTS: %v", err)
	}
	ready, check, checked := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		close(ready)
		<-check
		_, err := unix.SendmsgN(3, []byte("x"), unix.UnixRights(5), nil, 0)
		checked <- err
	}()
	<-ready
	poller, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.EpollCtl(poller, unix.EPOLL_CTL_ADD, 4, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: 4}); err != nil {
		t.Fatal(err)
	}
	if err := confinePreparation(); err != nil {
		t.Fatal(err)
	}
	close(check)
	if err := <-checked; !errors.Is(err, unix.EPERM) {
		t.Fatalf("existing thread escaped TSYNC: %v", err)
	}
	if _, err := unix.SendmsgN(3, []byte("x"), unix.UnixRights(5), nil, 0); !errors.Is(err, unix.EPERM) {
		t.Fatalf("SCM_RIGHTS export after filter: %v", err)
	}
	if _, _, _, _, err := unix.Recvmsg(4, data, ancillary, unix.MSG_DONTWAIT); !errors.Is(err, unix.EPERM) {
		t.Fatalf("queued SCM_RIGHTS import after filter: %v", err)
	}
	// A plain read consumes the payload but discards, rather than installs, the
	// ancillary rights. The ordinary stream/control transport remains usable.
	if n, err := unix.Read(4, data); err != nil || n != 1 || data[0] != 'q' {
		t.Fatalf("ordinary queued payload read: %q %d %v", data, n, err)
	}
	for _, number := range []uintptr{299, 307, 425, 426, 427} {
		if _, _, errno := unix.RawSyscall6(number, 0, 0, 0, 0, 0, 0); errno != unix.EPERM {
			t.Fatalf("ancillary/uring syscall %d: %v", number, errno)
		}
	}
	for _, fd := range []uintptr{3, 4, 5} {
		flags, err := unix.FcntlInt(fd, unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("descriptor %d not CLOEXEC: %d %v", fd, flags, err)
		}
	}
	if _, err := unix.Writev(3, [][]byte{[]byte("ordinary"), []byte("-write")}); err != nil {
		t.Fatal(err)
	}
	events := make([]unix.EpollEvent, 1)
	if n, err := unix.EpollWait(poller, events, 1000); err != nil || n != 1 || events[0].Fd != 4 {
		t.Fatalf("ordinary epoll: %d %v %+v", n, err, events)
	}
	unix.Close(poller)
	control := make([]byte, len("ordinary-write"))
	controlFile := os.NewFile(4, "control")
	if _, err := io.ReadFull(controlFile, control); err != nil || string(control) != "ordinary-write" {
		t.Fatalf("ordinary stream writev/read: %q %v", control, err)
	}
	message := preparationMessage(testPreparationConfig(t), PreparationFilterReady)
	if err := WritePreparationMessage(os.NewFile(3, "gate"), message); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadPreparationMessage(controlFile); err != nil || got != message {
		t.Fatalf("ordinary framed control writes: %+v %v", got, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(5, &st); err != nil {
		t.Fatal(err)
	}
	execPreparationTestChild(t, "postexec", fmt.Sprintf("%d:%d", st.Dev, st.Ino))
}

func execPreparationTestChild(t *testing.T, mode, inode string) {
	t.Helper()
	environment := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "GVX_PREPARATION_TEST_CHILD=") && !strings.HasPrefix(entry, "GVX_PREPARATION_TEST_INODE=") {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "GVX_PREPARATION_TEST_CHILD="+mode, "GVX_PREPARATION_TEST_INODE="+inode)
	if err := unix.Exec("/proc/self/exe", []string{os.Args[0], "-test.run=^TestPreparationFilterChild$"}, environment); err != nil {
		t.Fatal(err)
	}
}
