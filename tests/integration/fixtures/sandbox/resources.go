package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

func resourceSnapshot() map[string]any {
	var usage unix.Rusage
	err := unix.Getrusage(unix.RUSAGE_SELF, &usage)
	out := map[string]any{"uid": os.Getuid(), "gid": os.Getgid(), "go_threads_not_measured": true}
	if err == nil {
		out["user_cpu_us"] = usage.Utime.Sec*1000000 + usage.Utime.Usec
		out["system_cpu_us"] = usage.Stime.Sec*1000000 + usage.Stime.Usec
		out["maxrss_kib"] = usage.Maxrss
	}
	var limit unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_NPROC, &limit) == nil {
		out["nproc_soft"], out["nproc_hard"] = limit.Cur, limit.Max
	}
	if unix.Getrlimit(unix.RLIMIT_NOFILE, &limit) == nil {
		out["nofile_soft"], out["nofile_hard"] = limit.Cur, limit.Max
	}
	return out
}

func resourceProbe(ctx context.Context, c *scenarioConfig, p *probeSession) error {
	p.record(c.Kind, "before-workload", nil, resourceSnapshot())
	defer func() { p.record(c.Kind, "after-workload", nil, resourceSnapshot()) }()
	switch c.Kind {
	case "cpu":
		var work atomic.Uint64
		var wg sync.WaitGroup
		for i := range c.Workers {
			wg.Add(1)
			go func(seed uint64) {
				defer wg.Done()
				for ctx.Err() == nil {
					for range 4096 {
						seed = seed*6364136223846793005 + 1
					}
					work.Add(seed)
				}
			}(uint64(i + 1))
		}
		wg.Wait()
		p.record("cpu", "bounded-work-returned", ctx.Err(), map[string]any{"workers": c.Workers, "work_checksum": work.Load()})
		return ctx.Err()
	case "memory":
		p.record("memory", "allocation-intent-fatal-oom-possible", nil, map[string]any{"target_bytes": c.MemoryBytes})
		chunks := make([][]byte, 0, (c.MemoryBytes+(1<<20)-1)/(1<<20))
		var allocated int64
		for allocated < c.MemoryBytes && ctx.Err() == nil {
			n := min(int64(1<<20), c.MemoryBytes-allocated)
			b := make([]byte, int(n))
			for j := 0; j < len(b); j += 4096 {
				b[j] = 0xa5
			}
			b[len(b)-1] = 0xa5
			chunks = append(chunks, b)
			allocated += n
		}
		p.record("memory", "allocation-returned", ctx.Err(), map[string]any{"touched_bytes": allocated})
		err := waitUntil(ctx, time.Now().Add(time.Duration(c.HoldMS)*time.Millisecond))
		runtime.KeepAlive(chunks)
		return err
	case "fork":
		return forkProbe(ctx, c, p)
	case "thread":
		return threadProbe(ctx, c, p)
	case "identity":
		return identityProbe(ctx, p)
	}
	return errors.New("unknown resource fixture")
}

func forkProbe(ctx context.Context, c *scenarioConfig, p *probeSession) error {
	path, err := os.Executable()
	if err != nil {
		return err
	}
	children := make([]*exec.Cmd, 0, c.Attempts)
	defer func() {
		// Kill/reap only our exact child process handles. No name-based process kill.
		for _, cmd := range children {
			_ = cmd.Process.Kill()
		}
		failed, signaled := 0, 0
		for i, cmd := range children {
			waitErr := cmd.Wait()
			code := -1
			if cmd.ProcessState != nil {
				code = cmd.ProcessState.ExitCode()
			}
			if waitErr != nil {
				failed++
			}
			if code == -1 {
				signaled++
			}
			if i < 8 {
				p.record("fork-child", "reaped-first-eight-only", waitErr, map[string]any{"pid": cmd.Process.Pid, "exit_code": code})
			}
		}
		p.record("fork", "all-owned-children-reaped", nil, map[string]any{"children": len(children), "nonzero_or_signaled": failed, "signaled_or_no_exit_state": signaled})
	}()
	p.record("fork", "spawn-intent-fatal-task-exhaustion-possible", nil, map[string]any{"attempts": c.Attempts, "child_lifetime_ms": c.TimeoutSeconds * 1000})
	var spawnErr error
	for i := 0; i < c.Attempts && ctx.Err() == nil; i++ {
		cmd := exec.CommandContext(ctx, path, "--fixture-child-hold-ms="+strconv.Itoa(c.TimeoutSeconds*1000))
		cmd.Env = []string{}
		if spawnErr = cmd.Start(); spawnErr != nil {
			break
		}
		children = append(children, cmd)
	}
	p.record("fork", "spawn-returned", spawnErr, map[string]any{"children_started": len(children), "attempt_bound": c.Attempts})
	if err := waitUntil(ctx, time.Now().Add(time.Duration(c.HoldMS)*time.Millisecond)); err != nil {
		return err
	}
	return spawnErr
}

func threadProbe(ctx context.Context, c *scenarioConfig, p *probeSession) error {
	work, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	started := 0
	p.record("thread", "lock-thread-intent-runtime-fatal-possible", nil, map[string]any{"attempts": c.Attempts})
	for i := 0; i < c.Attempts && work.Err() == nil; i++ {
		ready := make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			close(ready)
			<-work.Done()
		}()
		select {
		case <-ready:
			started++
		case <-work.Done():
			return work.Err()
		}
		if started%16 == 0 {
			p.record("thread", "locked-so-far", nil, map[string]any{"locked_threads": started})
		}
	}
	p.record("thread", "lock-returned", work.Err(), map[string]any{"locked_threads": started})
	return waitUntil(work, time.Now().Add(time.Duration(c.HoldMS)*time.Millisecond))
}

// Identity mutations happen in a disposable child, never the serving process.
// Even an unexpectedly successful syscall cannot elevate subsequent probes.
type identityObservation struct {
	Operation string `json:"operation"`
	Outcome   string `json:"outcome"`
	Errno     int    `json:"errno"`
	Before    uint64 `json:"before,omitempty"`
	After     uint64 `json:"requested,omitempty"`
}

func identityProbe(ctx context.Context, p *probeSession) error {
	path, err := os.Executable()
	if err != nil {
		return err
	}
	for _, operation := range []string{"nproc-soft", "nproc-hard", "nofile-hard", "uid-root", "gid-root", "user-namespace", "mount-namespace", "pid-namespace", "network-namespace"} {
		if err := ctx.Err(); err != nil {
			return err
		}
		var out bytes.Buffer
		cmd := exec.CommandContext(ctx, path, "--fixture-identity="+operation)
		cmd.Env = []string{}
		cmd.Stdout = &out
		err := cmd.Run()
		var value identityObservation
		if err == nil && out.Len() <= 1024 && json.Unmarshal(out.Bytes(), &value) == nil && value.Operation == operation {
			p.record("identity", "child-syscall-observation", nil, map[string]any{"operation": value.Operation, "outcome": value.Outcome, "errno": value.Errno, "before": value.Before, "requested": value.After})
		} else {
			p.record("identity", "child-did-not-return-observation", err, map[string]any{"operation": operation})
		}
	}
	return ctx.Err()
}

func identityChild(operation string) {
	v := identityObservation{Operation: operation}
	var err error
	switch operation {
	case "nproc-soft", "nproc-hard", "nofile-hard":
		resource := unix.RLIMIT_NPROC
		if operation == "nofile-hard" {
			resource = unix.RLIMIT_NOFILE
		}
		var old unix.Rlimit
		err = unix.Getrlimit(resource, &old)
		if err == nil {
			next := old
			if operation == "nproc-soft" {
				v.Before = old.Cur
				if old.Cur == ^uint64(0) {
					v.Outcome = "already-infinite-no-raise-attempt"
					break
				}
				next.Cur++
				v.After = next.Cur
			} else {
				v.Before = old.Max
				if old.Max == ^uint64(0) {
					v.Outcome = "already-infinite-no-raise-attempt"
					break
				}
				next.Max++
				v.After = next.Max
			}
			err = unix.Setrlimit(resource, &next)
			if err == nil {
				_ = unix.Setrlimit(resource, &old)
			}
		}
	case "uid-root":
		err = unix.Setresuid(0, 0, 0)
	case "gid-root":
		err = unix.Setresgid(0, 0, 0)
	case "user-namespace":
		err = unix.Unshare(unix.CLONE_NEWUSER)
	case "mount-namespace":
		err = unix.Unshare(unix.CLONE_NEWNS)
	case "pid-namespace":
		err = unix.Unshare(unix.CLONE_NEWPID)
	case "network-namespace":
		err = unix.Unshare(unix.CLONE_NEWNET)
	default:
		os.Exit(87)
	}
	if v.Outcome == "" {
		v.Outcome, v.Errno = safeOutcome(err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(v)
}
