package cli

import (
	"errors"

	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/bundle"
	"github.com/thirdscam/chatanium/internal/portable/install"
)

func doctorCommand() *cobra.Command {
	doctor := &cobra.Command{Use: "doctor", Short: "Read-only inspection of portable runtime prerequisites", Args: cobra.NoArgs}
	doctor.RunE = func(cmd *cobra.Command, _ []string) error {
		result, err := install.Doctor(cmd.Context())
		return doctorResult(cmd, result, err)
	}
	jsonOutputFlag(doctor)
	return doctor
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
