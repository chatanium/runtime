package main

import (
	"context"
	"fmt"
	"os"

	"github.com/thirdscam/chatanium/internal/gvxstage"
)

func main() {
	var err error
	switch {
	case len(os.Args) == 2:
		err = gvxstage.Run(context.Background(), os.Args[1])
	case len(os.Args) == 3 && os.Args[1] == "--prepare":
		err = gvxstage.RunPreparation(context.Background(), os.Args[2])
	default:
		err = fmt.Errorf("one protected module or preparation configuration required")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gvx-stage:", err)
		os.Exit(125)
	}
}
