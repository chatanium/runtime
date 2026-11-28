package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/thirdscam/chatanium/internal/legacy/bootstrap"
	"github.com/thirdscam/chatanium/internal/portable/session"
)

func TestWorkerEntrypoint(t *testing.T) {
	const subprocess = "CHATANIUM_TEST_WORKER_ENTRYPOINT"
	if os.Getenv(subprocess) == "1" {
		os.Args = append(os.Args[:1], flag.Args()...)
		main()
		t.Fatal("worker accepted a missing INIT or unsupported arguments")
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "portable", args: []string{session.WorkerArg}},
		{name: "legacy"},
		{name: "unsupported", args: []string{"--unsupported"}},
		{name: "extra argument", args: []string{session.WorkerArg, "extra"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestWorkerEntrypoint$", "--"}, tc.args...)...)
			cmd.Env = append(os.Environ(), subprocess+"=1")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			var exit *exec.ExitError
			if err := cmd.Run(); !errors.As(err, &exit) || exit.ExitCode() != 125 {
				t.Fatalf("worker exit = %v, want status 125 (stderr: %q)", err, &stderr)
			}
			if got := stderr.String(); got != "chatanium-worker: lifecycle failed\n" {
				t.Fatalf("stderr = %q", got)
			}
			switch tc.name {
			case "portable":
				ev, err := session.ReadWorkerEvent(&stdout)
				if err != nil || ev.Type != "FAILED" || ev.Reason != "INVALID_INIT" {
					t.Fatalf("portable failure event = %+v, %v", ev, err)
				}
			case "legacy":
				if runtime.GOOS == "linux" {
					ev, err := bootstrap.ReadWorkerEvent(&stdout)
					if err != nil || ev.Type != "FAILED" || ev.Failure == nil || ev.Failure.Code != "WORKER_FAILED" {
						t.Fatalf("legacy failure event = %+v, %v", ev, err)
					}
				}
			}
			if stdout.Len() != 0 {
				t.Fatalf("unexpected stdout: %q", &stdout)
			}
		})
	}
}
