package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	legacyworker "github.com/thirdscam/chatanium/internal/legacy/worker"
	"github.com/thirdscam/chatanium/internal/portable/session"
	portableworker "github.com/thirdscam/chatanium/internal/portable/worker"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if err := runWorker(ctx, os.Stdin, os.Stdout, os.Stderr, os.Args[1:]...); err != nil {
		fmt.Fprintln(os.Stderr, "chatanium-worker: lifecycle failed")
		os.Exit(125)
	}
}

// The argument-free invocation is retained for Linux's existing v1 supervisor.
func runWorker(ctx context.Context, input io.Reader, output io.Writer, diagnostics io.Writer, args ...string) error {
	if len(args) == 1 && args[0] == session.WorkerArg {
		return portableworker.Run(ctx, input, output)
	}
	if len(args) != 0 {
		return errors.New("unsupported worker invocation")
	}
	return legacyworker.Run(ctx, input, output, diagnostics)
}
