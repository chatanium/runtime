package cmd

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/portable/install"
	"github.com/thirdscam/chatanium/internal/portable/session"
	"github.com/thirdscam/chatanium/internal/portable/store"
)

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

func doctorResult(cmd *cobra.Command, result map[string]any, checkErr error) error {
	view, human := operatorOutput(cmd)
	if !human {
		return errors.Join(checkErr, printJSON(cmd, result))
	}
	if result == nil {
		return checkErr
	}
	level, heading := logInfo, "Read-only runtime check"
	if checkErr != nil {
		level, heading = logWarn, "Read-only runtime check did not complete"
	}
	if err := view.log(level, heading); err != nil {
		return errors.Join(checkErr, err)
	}
	if path, ok := result["installation_directory"].(string); ok {
		if err := view.detail("Location", path); err != nil {
			return errors.Join(checkErr, err)
		}
	}
	if target, ok := result["bundle_target"].(bundle.PortableTarget); ok {
		engine, _ := result["pinned_engine"].(bundle.PortableEngine)
		if err := view.detail("Launcher", target.OS+"/"+target.Arch+"  "+target.Backend+"  GVX "+engine.Release); err != nil {
			return errors.Join(checkErr, err)
		}
	}
	if state, ok := result["installed_manifest_state"].(string); ok {
		verification, _ := result["installed_bundle_verification"].(string)
		switch verification {
		case "VERIFIED":
			state += " · installed files verified"
		case "FAILED":
			state += " · installed file verification failed"
		case "DIFFERENT_LAUNCHER":
			state += " · different launcher; installed files not verified"
		}
		if err := view.detail("Installation", state); err != nil {
			return errors.Join(checkErr, err)
		}
	} else if checkErr == nil {
		if err := view.detail("Installation", "Not set up yet. Run chatanium serve to begin."); err != nil {
			return err
		}
	}
	if checkErr != nil {
		return checkErr
	}
	return view.detail("Not tested", "Write access, GVX execution and sandbox isolation")
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
			if err := moduleView.log(level, message); err != nil {
				return err
			}
		}
		return nil
	}
}
