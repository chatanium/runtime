/*
Copyright © 2025 ANTEGRAL <antegral@antegral.net>
*/
package cmd

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/cmd/tui/newcmdinput"
	"github.com/thirdscam/chatanium/internal/scaffold"
)

var newCmd = &cobra.Command{
	Use:   "new",
	Short: "Create a new Chatanium v2 module",
	Long:  "Create an independent Go module using the public v2 SDK. Without --name, prompt interactively for its name.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		if name == "" {
			model, err := tea.NewProgram(newcmdinput.GetModel()).Run()
			if err != nil {
				return fmt.Errorf("run module name prompt: %w", err)
			}
			m, ok := model.(newcmdinput.Model)
			if !ok {
				return fmt.Errorf("unexpected module name prompt result")
			}
			name = m.GetValue()
			if name == "" {
				return fmt.Errorf("module name cannot be empty")
			}
		}
		directory, _ := cmd.Flags().GetString("output")
		sdk, _ := cmd.Flags().GetString("sdk-path")
		modulePath, _ := cmd.Flags().GetString("module-path")
		path, err := scaffold.Create(scaffold.Options{Name: name, Directory: directory, SDKPath: sdk, ModulePath: modulePath})
		if err != nil {
			return err
		}
		view := commandView(cmd, cmd.OutOrStdout())
		if err := view.status("OK", "Created a v2 module"); err != nil {
			return err
		}
		if err := view.detail("Location", path); err != nil {
			return err
		}
		return view.detail("Next", "Follow the generated README.md to build and package the module.")
	},
}

func init() {
	newCmd.Flags().String("name", "", "Module name (skip the interactive prompt)")
	newCmd.Flags().String("output", "", "New module directory (default modules/<name>)")
	newCmd.Flags().String("sdk-path", ".", "Local Chatanium v2 SDK checkout (default current directory)")
	newCmd.Flags().String("module-path", "", "Go module import path (default example.com/<name>)")
	addOperatorCommands("modules", newCmd)
}
