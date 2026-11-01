/*
Copyright © 2025 ANTEGRAL <antegral@antegral.net>
*/
package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/app"
	"github.com/thirdscam/chatanium/src/Util"
	"github.com/thirdscam/chatanium/src/Util/Log"
)

var startOptions app.StartOptions

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the supervised v2 modules",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := Util.InitEnv(); err != nil {
			return err
		}
		closeLog := Log.Init()
		defer closeLog()
		Log.Info.Println("Antegral/Chatanium: Dynamic Bot Management System")
		Log.Info.Println("Press CTRL+C to shutdown.")
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return app.Start(ctx, startOptions)
	},
}

func init() {
	flags := startCmd.Flags()
	flags.StringVar(&startOptions.ConfigPath, "config", "", "absolute operator JSON configuration")
	flags.StringVar(&startOptions.SupervisorSocket, "supervisor-socket", "", "absolute independently supervised host socket")
	flags.Int64Var(&startOptions.SupervisorUID, "supervisor-uid", -1, "trusted supervisor UID")
	flags.IntVar(&startOptions.SupervisorMaxBytes, "supervisor-max-bytes", 0, "supervisor packet bound")
	flags.DurationVar(&startOptions.Duration, "duration", 0, "optional finite observation duration before orderly stop")
	rootCmd.AddCommand(startCmd)
}
