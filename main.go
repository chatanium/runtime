package main

import (
	"fmt"
	"os"

	"github.com/thirdscam/chatanium/cmd"
	"github.com/thirdscam/chatanium/internal/portable/process"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == process.GuardianArg {
		if err := process.RunGuardian(); err != nil {
			fmt.Fprintln(os.Stderr, "chatanium: child guardian:", err)
			os.Exit(1)
		}
		return
	}
	cmd.Execute()
}
