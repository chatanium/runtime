/*
Copyright © 2025 ANTEGRAL <antegral@antegral.net>
*/
package cli

import (
	"errors"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/cli/tui/newcmdinput"
	"github.com/thirdscam/chatanium/internal/scaffold"
)

var newCmd = &cobra.Command{
	Use:   "new",
	Short: "Create a new Chatanium v2 module",
	Long:  "Create an independent Go module using the public v2 SDK. Without --name, choose a starter and review the output path interactively.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		directory, _ := cmd.Flags().GetString("output")
		sdk, _ := cmd.Flags().GetString("sdk-path")
		modulePath, _ := cmd.Flags().GetString("module-path")
		starter, _ := cmd.Flags().GetString("template")
		opts := scaffold.Options{
			Name: name, Directory: directory, SDKPath: sdk, ModulePath: modulePath,
			Template: scaffold.Template(starter),
		}
		if opts.Template != scaffold.Local && opts.Template != scaffold.Discord {
			return fmt.Errorf("invalid --template %q; choose local or discord", starter)
		}
		if !cmd.Flags().Changed("name") {
			prompt := tea.NewProgram(newcmdinput.New(opts),
				tea.WithContext(cmd.Context()), tea.WithInput(cmd.InOrStdin()), tea.WithOutput(cmd.OutOrStdout()))
			model, err := prompt.Run()
			if errors.Is(err, tea.ErrInterrupted) || cmd.Context().Err() != nil {
				return nil
			}
			if err != nil {
				return fmt.Errorf("run module setup prompt: %w", err)
			}
			result, ok := model.(newcmdinput.Model)
			if !ok {
				return fmt.Errorf("unexpected module setup prompt result")
			}
			var confirmed bool
			opts, confirmed = result.Result()
			if !confirmed {
				return nil
			}
		}
		path, err := scaffold.Create(opts)
		if err != nil {
			return err
		}
		view := commandView(cmd, cmd.OutOrStdout())
		if err := view.log(logInfo, "Created a v2 module"); err != nil {
			return err
		}
		if err := view.detail("Location", path); err != nil {
			return err
		}
		if target := scaffold.BuildTarget(sdk, path); target != "" {
			return view.detail("Next", "From the SDK checkout, run make modules MODULE="+target)
		}
		return view.detail("Next", "See README.md for the repo-relative path required by make modules.")
	},
}

func init() {
	newCmd.Flags().String("name", "", "Module name (skip the interactive prompt)")
	newCmd.Flags().String("output", "", "New module directory (default local-modules/<name>)")
	newCmd.Flags().String("sdk-path", ".", "Local Chatanium v2 SDK checkout (default current directory)")
	newCmd.Flags().String("module-path", "", "Go module import path (default example.com/<name>)")
	newCmd.Flags().String("template", string(scaffold.Local), "Starter template: local or discord")
	addOperatorCommands("modules", newCmd)
}
