package cmd

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/portable/install"
	"github.com/thirdscam/chatanium/internal/portable/service"
	"github.com/thirdscam/chatanium/internal/portable/session"
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
		if errors.Is(err, errResetDeclined) {
			if _, human := operatorOutput(cmd); human {
				return nil
			}
			err = nil
		}
		if errors.Is(err, errSetupDeclined) {
			return reportSetupDeclined(cmd)
		}
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
				if err := commandView(cmd, cmd.ErrOrStderr()).status("INFO", "Using the existing configuration; first-use options were not applied."); err != nil {
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
			confirm := setupApproval(cmd, approvalInput(cmd), m == nil && first == nil)
			if m == nil {
				created, err := install.Init(cmd.Context(), *budget, first, confirm)
				if errors.Is(err, errSetupDeclined) {
					return reportSetupDeclined(cmd)
				}
				if err != nil {
					return err
				}
				m = &created
			}
			if m.State == store.Initializing {
				err := install.SetupForServe(cmd.Context(), path, *m, first, confirm)
				if errors.Is(err, errSetupDeclined) {
					return reportSetupDeclined(cmd)
				}
				if err != nil {
					return err
				}
			}
		}
		view, human := operatorOutput(cmd)
		var observe func(session.WorkerEvent) error
		if human {
			if err := view.status("START", "Starting Chatanium"); err != nil {
				return err
			}
			observe = terminalWorkerEvents(view)
		} else {
			encoder := json.NewEncoder(cmd.OutOrStdout())
			observe = func(event session.WorkerEvent) error { return encoder.Encode(event) }
		}
		if err := service.Run(cmd.Context(), path, m.ID, *duration, observe, cmd.ErrOrStderr()); err != nil {
			return err
		}
		if human {
			return view.status("STOPPED", "Chatanium stopped.")
		}
		return nil
	}
	return cmd
}

func setupFlags(cmd *cobra.Command) (*int64, func() (*install.FirstModule, error)) {
	budget := cmd.Flags().Int64("budget-bytes", install.DefaultBudgetBytes, "maximum simultaneous installation-owned bytes")
	image := imageFlags(cmd)
	module := moduleFlags(cmd, false)
	approvalFlag(cmd)
	jsonOutputFlag(cmd)
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
