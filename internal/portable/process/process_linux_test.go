//go:build linux && !android && (amd64 || arm64)

package process

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const fixtureArg = "__portable-native-lifetime-fixture"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case GuardianArg:
			if filepath.Base(os.Args[0]) == "reporting-guardian" {
				fmt.Fprintln(os.Stderr, os.Getpid())
			}
			if err := RunGuardian(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		case fixtureArg:
			if err := runFixture(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}
	}
	os.Exit(m.Run())
}

func runFixture(args []string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	switch args[0] {
	case "owner":
		lock, err := Lock(args[1])
		if err != nil {
			return err
		}
		defer lock.Close()
		child, err := Start(self, Spec{Path: self, Args: []string{fixtureArg, "root"}, Stdout: os.Stdout, Stderr: os.Stderr, OwnerLock: lock})
		if err != nil {
			return err
		}
		return child.Wait()
	case "root":
		if len(os.Environ()) != 0 {
			return errors.New("managed executable inherited the owner's ambient environment")
		}
		leaf := exec.Command(self, fixtureArg, "detached")
		leaf.Env = []string{}
		leaf.Stdout, leaf.Stderr = os.Stdout, os.Stderr
		leaf.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := leaf.Start(); err != nil {
			return err
		}
	case "detached":
		if _, err := fmt.Fprintln(os.Stdout, "detached ready"); err != nil {
			return err
		}
	case "original":
		if _, err := fmt.Fprintln(os.Stdout, "original ready"); err != nil {
			return err
		}
	default:
		return errors.New("unknown process fixture")
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestGuardianReapsDetachedWriterAfterOwnerDeath(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(t.TempDir(), "private")
	if err := EnsurePrivateDir(private); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(private, "owner.lock")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	deadline := time.Now().Add(10 * time.Second)
	if err := r.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	owner := exec.CommandContext(ctx, self, fixtureArg, "owner", lockPath)
	owner.Stdout, owner.Stderr = w, os.Stderr
	if err := owner.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if owner.ProcessState == nil {
			_ = owner.Process.Kill()
			_ = owner.Wait()
		}
	}()
	w.Close()
	reader := bufio.NewReader(r)
	line, err := reader.ReadString('\n')
	if err != nil || line != "detached ready\n" {
		t.Fatalf("detached writer readiness: %q, %v", line, err)
	}
	if lock, err := Lock(lockPath); !errors.Is(err, ErrOwnerBusy) {
		if lock != nil {
			lock.Close()
		}
		t.Fatalf("want owner lock held during execution, got %v", err)
	}
	if err := owner.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = owner.Wait()
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("detached descendant kept pipe open after owner death: %v", err)
	}
	for {
		lock, err := Lock(lockPath)
		if err == nil {
			lock.Close()
			break
		}
		if !errors.Is(err, ErrOwnerBusy) || ctx.Err() != nil {
			t.Fatalf("guardian never released its lock after cleanup: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestGuardianLossTerminatesOriginalWithoutClaimingScopeProof(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	guardian := filepath.Join(t.TempDir(), "reporting-guardian")
	if err := os.Symlink(self, guardian); err != nil {
		t.Fatal(err)
	}
	newPipe := func() (*os.File, *os.File) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { r.Close(); w.Close() })
		if err := r.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		return r, w
	}
	rootR, rootW := newPipe()
	guardR, guardW := newPipe()
	child, err := Start(guardian, Spec{Path: self, Args: []string{fixtureArg, "original"}, Stdout: rootW, Stderr: guardW})
	rootW.Close()
	guardW.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = child.Stop(ctx, nil)
	})
	root := bufio.NewReader(rootR)
	if ready, err := root.ReadString('\n'); err != nil || ready != "original ready\n" {
		t.Fatalf("managed executable readiness: %q, %v", ready, err)
	}
	rawPID, err := bufio.NewReader(guardR).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(rawPID))
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := root.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("original executable kept writing after guardian death: %v", err)
	}
	select {
	case <-child.Done():
		if child.Observed() || !errors.Is(child.Wait(), ErrUnobserved) {
			t.Fatalf("lost guardian must not attest whole-scope exit: %v", child.Wait())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("supervisor did not detect guardian loss")
	}
}
