package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/thirdscam/chatanium/internal/provision"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if len(os.Args) == 2 && os.Args[1] == provision.PortableGuestArg {
		if err := provision.RunPortablePreparer(ctx, os.Stdin, os.Stdout, os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "portable image preparation failed: %v\n", err)
			os.Exit(125)
		}
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "gvx-preparer accepts private stdin only")
		os.Exit(125)
	}
	if err := provision.RunPreparer(ctx, os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "image preparation failed")
		os.Exit(125)
	}
}
