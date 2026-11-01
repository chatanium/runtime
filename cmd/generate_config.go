package cmd

import (
	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/app"
)

var generateConfigOptions app.GenerateConfigOptions

var generateConfigCmd = &cobra.Command{
	Use:   "generate-config",
	Short: "Generate an approved v2 installation configuration",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return app.GenerateConfig(cmd.Context(), generateConfigOptions)
	},
}

func init() {
	flags := generateConfigCmd.Flags()
	flags.StringVar(&generateConfigOptions.Base, "base", "", "absolute host configuration with modules:[]")
	flags.StringVar(&generateConfigOptions.ModuleConfig, "module-config", "", "absolute module-scoped JSON file")
	flags.StringVar(&generateConfigOptions.Approval, "approval", "", "absolute protobuf-JSON Grants file")
	flags.StringVar(&generateConfigOptions.Image, "image", "", "real immutable registry/repository@sha256 digest")
	flags.StringVar(&generateConfigOptions.ModuleID, "module-id", "", "stable operator-assigned module ID")
	flags.StringVar(&generateConfigOptions.Entrypoint, "entrypoint", "", "approved image executable absolute path")
	flags.UintVar(&generateConfigOptions.UID, "uid", 0, "approved nonzero module UID")
	flags.UintVar(&generateConfigOptions.GID, "gid", 0, "approved nonzero module GID")
	flags.StringVar(&generateConfigOptions.ConfigRevision, "config-revision", "", "operator configuration revision")
	flags.StringVar(&generateConfigOptions.ApprovalRevision, "approval-revision", "", "operator approval revision")
	flags.StringVar(&generateConfigOptions.SupervisorSocket, "supervisor-socket", "", "absolute real supervisor socket for image verification")
	flags.Int64Var(&generateConfigOptions.SupervisorUID, "supervisor-uid", -1, "trusted supervisor UID")
	flags.IntVar(&generateConfigOptions.SupervisorMaxBytes, "supervisor-max-bytes", 0, "supervisor packet bound")
	rootCmd.AddCommand(generateConfigCmd)
}
