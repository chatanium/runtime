package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// TestMain keeps the integration-only CLI mode separate from ordinary tests.
// Invoke a root test executable with:
// --integration-runtime-return-hold <seconds:1..60> -- start <real start arguments>
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "--integration-runtime-return-hold" {
		code := runIntegrationRuntimeReturnHold(os.Args[2:])
		if code == 2 {
			fmt.Fprintln(os.Stderr, "integration runtime return-hold invocation or marker failed")
		}
		os.Exit(code)
	}
	os.Exit(m.Run())
}

func runIntegrationRuntimeReturnHold(args []string) int {
	if len(args) < 3 || args[1] != "--" || args[2] != "start" {
		return 2
	}
	seconds, err := strconv.Atoi(args[0])
	if err != nil || seconds < 1 || seconds > 60 {
		return 2
	}
	var options StartOptions
	flags := flag.NewFlagSet("start", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.ConfigPath, "config", "", "")
	flags.StringVar(&options.SupervisorSocket, "supervisor-socket", "", "")
	flags.Int64Var(&options.SupervisorUID, "supervisor-uid", -1, "")
	flags.IntVar(&options.SupervisorMaxBytes, "supervisor-max-bytes", 0, "")
	flags.DurationVar(&options.Duration, "duration", 0, "")
	if flags.Parse(args[3:]) != nil || flags.NArg() != 0 {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// This is the actual runtime owner, not a child process or a test result.
	// Do not serialize the returned error: it may contain operator data.
	code, class := 0, "ok"
	if Start(ctx, options) != nil {
		code, class = 1, "error"
	}
	_, markerErr := fmt.Fprintf(os.Stdout, "{\"integration\":\"runtime-return-hold\",\"phase\":\"returned\",\"pid\":%d,\"class\":\"%s\",\"exit_code\":%d}\n", os.Getpid(), class, code)

	// Retain this exact PID for a finite post-return observation window, even
	// after failure. No m.Run result can replace the actual runtime outcome.
	time.Sleep(time.Duration(seconds) * time.Second)
	if markerErr != nil {
		return 2
	}
	return code
}
