package cli

import (
	"errors"

	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/portable/install"
)

func configureCommand() *cobra.Command {
	configure := installedCommand("configure", "Review each prepared module and publish a stopped configuration", func(cmd *cobra.Command, path string) error {
		candidatePath, _ := cmd.Flags().GetString("config")
		raw, err := install.ReadInput(candidatePath)
		if err != nil {
			return err
		}
		candidate, err := install.DecodeCandidate(raw)
		if err != nil {
			return err
		}
		m, err := install.Configure(cmd.Context(), path, candidate, approval(cmd))
		return manifestResult(cmd, m, err)
	})
	configure.Flags().String("config", "", "canonical absolute path to the generate-config candidate")
	approvalFlag(configure)
	jsonOutputFlag(configure)
	return configure
}

func inspectConfigCommand() *cobra.Command {
	return installedCommand("inspect-config", "Read the exact portable installation configuration", func(cmd *cobra.Command, path string) error {
		i, err := install.Open(path)
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(i.Manifest.Config)
		return errors.Join(err, i.Close())
	})
}

func generateConfigCommand() *cobra.Command {
	var read func() (install.GenerateOptions, error)
	command := installedCommand("generate-config", "Generate an unapproved configuration candidate for a staged image", func(cmd *cobra.Command, path string) error {
		p, err := read()
		if err != nil {
			return err
		}
		candidate, err := install.GenerateConfig(path, p)
		if err != nil {
			return err
		}
		return printJSON(cmd, candidate)
	})
	read = moduleFlags(command, true)
	return command
}

func moduleFlags(command *cobra.Command, includeImageID bool) func() (install.GenerateOptions, error) {
	var options install.GenerateOptions
	var modulePath, grantPath, networkPath string
	flags := command.Flags()
	if includeImageID {
		flags.StringVar(&options.ImageID, "image", "", "staged image ID returned by prepare-image")
	}
	flags.StringVar(&options.ModuleID, "module-id", "", "stable module identity")
	flags.Uint32Var(&options.UID, "uid", 1000, "approved nonroot guest UID")
	flags.Uint32Var(&options.GID, "gid", 1000, "approved nonroot guest GID")
	flags.StringVar(&modulePath, "module-config", "", "canonical absolute module configuration JSON path")
	flags.StringVar(&grantPath, "approval", "", "canonical absolute proposed core-v2 grants JSON path")
	flags.StringVar(&networkPath, "network-profile", "", "explicit portable PUBLIC_INTERNET profile JSON (omit for NONE)")
	return func() (install.GenerateOptions, error) {
		p := options
		var err error
		p.ModuleConfig, err = install.ReadInput(modulePath)
		if err != nil {
			return install.GenerateOptions{}, err
		}
		p.Grant, err = install.ReadInput(grantPath)
		if err != nil {
			return install.GenerateOptions{}, err
		}
		if networkPath != "" {
			data, err := install.ReadInput(networkPath)
			if err != nil {
				return install.GenerateOptions{}, err
			}
			if err := gvxcontract.DecodeStrict(data, 256<<10, 8, &p.Network); err != nil {
				return install.GenerateOptions{}, err
			}
		}
		return p, nil
	}
}
