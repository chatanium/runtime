package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/portable/install"
	"github.com/thirdscam/chatanium/internal/portable/session"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

func printJSON(cmd *cobra.Command, value any) error {
	return json.NewEncoder(cmd.OutOrStdout()).Encode(value)
}

func manifestResult(cmd *cobra.Command, m install.Manifest, err error) error {
	if err != nil {
		return err
	}
	if view, human := operatorOutput(cmd); human {
		return manifestStatus(view, cmd, m)
	}
	return printJSON(cmd, struct {
		State      string `json:"state"`
		PlanDigest string `json:"plan_digest"`
		ConfigPlan string `json:"config_plan_digest,omitempty"`
		Revision   string `json:"configuration_revision,omitempty"`
		Modules    int    `json:"modules"`
	}{m.State, m.PlanDigest, m.ConfigPlanDigest, m.Revision, len(m.Modules)})
}

func operatorResult(cmd *cobra.Command, message string, jsonValue any) error {
	if view, human := operatorOutput(cmd); human {
		return view.log(logInfo, message)
	}
	return printJSON(cmd, jsonValue)
}

func manifestStatus(view terminalView, cmd *cobra.Command, m install.Manifest) error {
	switch cmd.Name() {
	case "init":
		if err := view.log(logInfo, "Installation ready to serve."); err != nil {
			return err
		}
		return view.detail("Next", "chatanium serve")
	case "configure":
		return view.log(logInfo, fmt.Sprintf("Saved configuration for %d module(s). Run chatanium serve to start.", len(m.Modules)))
	case "update":
		if m.State == store.Initializing {
			return view.log(logInfo, "Runtime is installed. Review the configuration before serving modules.")
		}
		return view.log(logInfo, "Runtime is already up to date.")
	case "uninstall":
		return view.log(logInfo, "Removed installed code. Configuration, image cache, module data and backups were kept.")
	default:
		return view.log(logInfo, m.State)
	}
}

type moduleDiagnostics struct {
	view terminalView
}

func (d moduleDiagnostics) Write(p []byte) (int, error) {
	view := d.view
	view.area = "MODULE"
	if err := view.log(logError, strings.TrimSuffix(string(p), "\n")); err != nil {
		return 0, err
	}
	return len(p), nil
}

func terminalWorkerEvents(view terminalView) func(session.WorkerEvent) error {
	previous := make(map[string]session.ModuleStatus)
	moduleView := view
	moduleView.area = "MODULE"
	return func(event session.WorkerEvent) error {
		switch event.Type {
		case "READY":
			message := "Chatanium is running in the foreground."
			if len(event.Modules) == 0 {
				message = "Chatanium is running in the foreground. No modules are configured."
			}
			if err := view.log(logInfo, message); err != nil {
				return err
			}
			if err := view.detail("Stop", "Ctrl+C or chatanium stop from another terminal"); err != nil {
				return err
			}
		case "STATUS":
			if event.Reason == "BACKEND_ERROR" {
				if err := view.log(logError, "A configured backend reported an error."); err != nil {
					return err
				}
			}
		case "DRAINED":
			return view.log(logDebug, "Worker drained. Finishing shutdown.")
		case "FAILED":
			// The command error reports the worker reason after cleanup.
		}
		for _, module := range event.Modules {
			if previous[module.ModuleID] == module {
				continue
			}
			previous[module.ModuleID] = module
			level := logDebug
			switch module.State {
			case "RUNNING", "STOPPED":
				level = logInfo
			case "FAILED":
				level = logError
			}
			message := strconv.Quote(module.ModuleID) + " · " + strings.ToLower(strings.ReplaceAll(module.State, "_", " "))
			if module.Reason != "" {
				message += " · " + strings.ToLower(strings.ReplaceAll(module.Reason, "_", " "))
			}
			if module.DiscordAccessDenied {
				message += " · Discord access: none"
			}
			if err := moduleView.log(level, message); err != nil {
				return err
			}
		}
		return nil
	}
}
