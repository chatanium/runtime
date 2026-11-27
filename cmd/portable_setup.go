package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/portable/install"
	"github.com/thirdscam/chatanium/internal/portable/service"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

func initCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "init", Aliases: []string{"reset"}, Short: "Set up a stopped runtime or confirm resetting an existing installation", Args: cobra.NoArgs}
	cmd.SetFlagErrorFunc(legacyFlagError)
	budget, firstModule := setupFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		first, err := firstModule()
		if err != nil {
			return err
		}
		m, err := initializeOrReset(cmd, *budget, first)
		return manifestResult(cmd, m, err)
	}
	return cmd
}

func serveCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "serve", Short: "Set up the portable runtime if needed, then serve in the foreground", Args: cobra.NoArgs}
	cmd.SetFlagErrorFunc(legacyFlagError)
	duration := cmd.Flags().Duration("duration", 0, "optional observation duration before orderly shutdown")
	budget, firstModule := setupFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if *duration < 0 {
			return errors.New("serve duration must be nonnegative")
		}
		path, err := install.Directory()
		if err != nil {
			return err
		}
		m, err := install.InstalledManifest(path)
		if err != nil {
			return err
		}
		if m != nil && m.State == store.Ready {
			if initialModuleRequested(cmd) || cmd.Flags().Changed("budget-bytes") || cmd.Flags().Changed("approve") {
				if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "Using the existing configuration; first-use options were not applied."); err != nil {
					return err
				}
			}
		} else {
			if m != nil {
				if m.State != store.Initializing {
					return fmt.Errorf("cannot serve installation in state %s; retained data was not changed", m.State)
				}
				if cmd.Flags().Changed("budget-bytes") && *budget != m.BudgetBytes {
					return errors.New("the installation already has a different approved disk budget")
				}
			}
			first, err := firstModule()
			if err != nil {
				return err
			}
			confirm := approval(cmd)
			if m == nil {
				created, err := install.Init(cmd.Context(), *budget, first, confirm)
				if err != nil {
					return err
				}
				m = &created
			}
			if m.State == store.Initializing {
				if err := install.SetupForServe(cmd.Context(), path, *m, first, confirm); err != nil {
					return err
				}
			}
		}
		return service.Run(cmd.Context(), path, m.ID, *duration, cmd.OutOrStdout(), cmd.ErrOrStderr())
	}
	return cmd
}

func setupFlags(cmd *cobra.Command) (*int64, func() (*install.FirstModule, error)) {
	budget := cmd.Flags().Int64("budget-bytes", install.DefaultBudgetBytes, "maximum simultaneous installation-owned bytes")
	image := imageFlags(cmd)
	module := moduleFlags(cmd, false)
	approvalFlag(cmd)
	return budget, func() (*install.FirstModule, error) {
		if !initialModuleRequested(cmd) {
			return nil, nil
		}
		i, err := image()
		if err != nil {
			return nil, err
		}
		m, err := module()
		if err != nil {
			return nil, err
		}
		return &install.FirstModule{Image: i, Module: m}, nil
	}
}
