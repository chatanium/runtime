//go:build linux

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/gvxipc"
)

func main() {
	if len(os.Args) != 2 || (os.Args[1] != gvxcontract.BridgeLegacyArg && os.Args[1] != gvxcontract.BridgePortableArg) {
		gvxipc.ReportBootstrapFailure(os.Stderr, "arguments", nil)
		os.Exit(125)
	}
	signal.Ignore(syscall.SIGPIPE)
	limits, timeout, err := gvxipc.BootstrapLimits()
	if err != nil {
		if os.Args[1] == gvxcontract.BridgePortableArg {
			gvxipc.ReportBootstrapFailure(os.Stderr, "limits", err)
		}
		os.Exit(125)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if os.Args[1] == gvxcontract.BridgePortableArg {
		os.Exit(gvxipc.RunPortableGuest(ctx, os.Stdin, os.Stdout, os.Stderr, limits, timeout))
	}
	os.Exit(gvxipc.RunGuest(ctx, os.Stdin, os.Stdout, os.Stderr, limits, timeout))
}
