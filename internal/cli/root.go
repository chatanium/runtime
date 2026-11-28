/*
Copyright © 2024 ANTEGRAL <antegral@antegral.net>
*/
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:           "chatanium",
	Short:         "Portable chatbot runtime",
	Long:          "Run and manage GVX-isolated chatbot modules from your user account.",
	SilenceErrors: true,
	SilenceUsage:  true,
}

func init() {
	rootCmd.AddGroup(
		&cobra.Group{ID: "runtime", Title: "Runtime:"},
		&cobra.Group{ID: "modules", Title: "Modules:"},
		&cobra.Group{ID: "maintenance", Title: "Maintenance:"},
		&cobra.Group{ID: "other", Title: "Other:"},
	)
	rootCmd.SetHelpCommandGroupID("other")
	rootCmd.SetCompletionCommandGroupID("other")
}

func addOperatorCommands(group string, commands ...*cobra.Command) {
	for _, command := range commands {
		command.GroupID = group
	}
	rootCmd.AddCommand(commands...)
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	command, err := rootCmd.ExecuteContextC(ctx)
	if err != nil {
		view := commandView(command, command.ErrOrStderr())
		machine, _ := command.Flags().GetBool("json")
		if view.terminal && !machine {
			_ = view.log(logError, err.Error())
		} else {
			fmt.Fprintln(command.ErrOrStderr(), "Error:", err)
		}
		os.Exit(1)
	}
}
