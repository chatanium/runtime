package main

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// The production runner sets trusted Entrypoint/Cmd itself. The derived fixture
// image therefore uses only these fixed, non-reserved image environment inputs.
// argv is also supported for an operator running the fixture executable directly.
// Neither route pretends config can be fetched before the go-plugin handshake.
func fixtureProcessMode(args []string) bool {
	if len(args) == 1 && args[0] == "--fixture-ipc-component" {
		ipcComponentBootstrap()
		return false
	}
	if len(args) == 1 && strings.HasPrefix(args[0], "--fixture-child-hold-ms=") {
		ms, err := strconv.Atoi(strings.TrimPrefix(args[0], "--fixture-child-hold-ms="))
		if err != nil || ms < 1 || ms > 120000 {
			os.Exit(87)
		}
		_ = waitUntil(context.Background(), time.Now().Add(time.Duration(ms)*time.Millisecond))
		return true
	}
	if len(args) == 1 && strings.HasPrefix(args[0], "--fixture-identity=") {
		identityChild(strings.TrimPrefix(args[0], "--fixture-identity="))
		return true
	}
	mode := os.Getenv("FLEXMODULE_FIXTURE_BOOTSTRAP_MODE")
	bytesText := os.Getenv("FLEXMODULE_FIXTURE_BOOTSTRAP_BYTES")
	timeoutText := os.Getenv("FLEXMODULE_FIXTURE_BOOTSTRAP_TIMEOUT_SECONDS")
	if len(args) != 0 {
		if len(args) != 3 || !strings.HasPrefix(args[0], "--fixture-bootstrap=") || !strings.HasPrefix(args[1], "--fixture-bootstrap-bytes=") || !strings.HasPrefix(args[2], "--fixture-bootstrap-timeout-seconds=") {
			os.Exit(87)
		}
		mode = strings.TrimPrefix(args[0], "--fixture-bootstrap=")
		bytesText = strings.TrimPrefix(args[1], "--fixture-bootstrap-bytes=")
		timeoutText = strings.TrimPrefix(args[2], "--fixture-bootstrap-timeout-seconds=")
	}
	if mode == "" && bytesText == "" && timeoutText == "" {
		return false
	}
	n, err := strconv.ParseInt(bytesText, 10, 64)
	seconds, timeErr := strconv.Atoi(timeoutText)
	if err != nil || timeErr != nil || n < 1 || n > 64<<20 || seconds < 1 || seconds > 30 {
		os.Exit(87)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
	defer cancel()
	switch mode {
	case "invalid":
		// Deliberately invalid first stdout line; never call Serve afterward.
		err = boundedLiteral(ctx, int(os.Stdout.Fd()), []byte("invalid-fixture-handshake\n"))
	case "oversized":
		_, err = boundedOutput(ctx, int(os.Stdout.Fd()), n)
		if err == nil {
			err = boundedLiteral(ctx, int(os.Stdout.Fd()), []byte{'\n'})
		}
	case "no-newline":
		_, err = boundedOutput(ctx, int(os.Stdout.Fd()), n)
		if err == nil {
			err = waitUntil(ctx, time.Now().Add(time.Duration(seconds)*time.Second))
		}
	case "stderr-before-handshake":
		_, err = boundedOutput(ctx, int(os.Stderr.Fd()), n)
		if err == nil {
			return false // The very first stdout bytes still belong to real Serve.
		}
	default:
		os.Exit(87)
	}
	// There is no authenticated storage yet; parent attach/exit records are the
	// evidence for bootstrap variants. Never print config, environment, or errors.
	_ = err
	os.Exit(88)
	return true
}

func floodProbe(ctx context.Context, c *scenarioConfig, p *probeSession) error {
	p.record("flood", "bounded-output-intent", nil, map[string]any{"stdout_target_bytes": c.StdoutBytes, "stderr_target_bytes": c.StderrBytes})
	var wg sync.WaitGroup
	errs := make([]error, 2)
	counts := make([]int64, 2)
	for i, target := range []int64{c.StdoutBytes, c.StderrBytes} {
		wg.Add(1)
		go func(i int, target int64) {
			defer wg.Done()
			// Serve replaces os.Stdout/os.Stderr with broker pipes; those are
			// intentionally discarded by the runtime. Exercise Docker attach
			// using the original process descriptors, not the broker streams.
			fd := unix.Stdout
			if i == 1 {
				fd = unix.Stderr
			}
			counts[i], errs[i] = boundedOutput(ctx, fd, target)
		}(i, target)
	}
	wg.Wait()
	for i, stream := range []string{"stdout", "stderr"} {
		p.record("flood", "stream-write-returned", errs[i], map[string]any{"stream": stream, "written_bytes": counts[i], "transport": "process-fds"})
	}
	if errs[0] != nil {
		return errs[0]
	}
	return errs[1]
}

// Raw nonblocking writes are important: an ordinary os.File.Write may remain
// stuck behind a stopped attach reader despite the scenario's finite deadline.
// No unbounded log string is allocated; all output is a fixed synthetic pattern.
func boundedOutput(ctx context.Context, fd int, target int64) (int64, error) {
	block := make([]byte, 4096)
	for i := range block {
		block[i] = 'x'
	}
	return boundedWrite(ctx, fd, block, target)
}

func boundedLiteral(ctx context.Context, fd int, b []byte) error {
	_, err := boundedWrite(ctx, fd, b, int64(len(b)))
	return err
}

func boundedWrite(ctx context.Context, fd int, block []byte, target int64) (int64, error) {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return 0, err
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags|unix.O_NONBLOCK); err != nil {
		return 0, err
	}
	defer func() { _, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags) }()
	var written int64
	for written < target {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		n := int(min(int64(len(block)), target-written))
		count, err := unix.Write(fd, block[:n])
		if count > 0 {
			written += int64(count)
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			if err := waitUntil(ctx, time.Now().Add(time.Millisecond)); err != nil {
				return written, err
			}
			continue
		}
		if err != nil {
			return written, err
		}
		if count == 0 {
			return written, errors.New("zero-byte fixture output write")
		}
	}
	return written, nil
}
