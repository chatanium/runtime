package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/thirdscam/chatanium/internal/app"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if err := app.RunWorker(ctx, os.Stdin, os.Stdout, os.Stderr, os.Args[1:]...); err != nil {
		fmt.Fprintln(os.Stderr, "chatanium-worker: lifecycle failed")
		os.Exit(125)
	}
}
