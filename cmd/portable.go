package cmd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/portable/images"
	"github.com/thirdscam/chatanium/internal/portable/install"
	"github.com/thirdscam/chatanium/internal/portable/service"
)

func init() {
	doctor := &cobra.Command{Use: "doctor", Short: "Read-only inspection of portable runtime prerequisites", Args: cobra.NoArgs}
	doctor.RunE = func(cmd *cobra.Command, _ []string) error {
		result, err := install.Doctor(cmd.Context())
		return errors.Join(err, printJSON(cmd, result))
	}
	initialize := &cobra.Command{Use: "init", Short: "Review and create a private, stopped portable installation", Args: cobra.NoArgs}
	approvalFlag(initialize)
	initialize.SetFlagErrorFunc(legacyFlagError)
	initialize.Flags().Int64("budget-bytes", install.DefaultBudgetBytes, "maximum simultaneous installation-owned bytes")
	imageArgs := imageFlags(initialize)
	moduleArgs := moduleFlags(initialize, false)
	initialize.RunE = func(cmd *cobra.Command, _ []string) error {
		budget, _ := cmd.Flags().GetInt64("budget-bytes")
		var first *install.FirstModule
		if initialModuleRequested(cmd) {
			first = new(install.FirstModule)
			var err error
			first.Image, err = imageArgs()
			if err != nil {
				return err
			}
			first.Module, err = moduleArgs()
			if err != nil {
				return err
			}
		}
		m, err := install.Init(cmd.Context(), budget, first, approval(cmd))
		return manifestResult(cmd, m, err)
	}
	serve := installedCommand("serve", "Run the portable supervisor in the foreground", func(cmd *cobra.Command, path string) error {
		duration, _ := cmd.Flags().GetDuration("duration")
		if duration < 0 {
			return errors.New("serve duration must be nonnegative")
		}
		return service.Run(cmd.Context(), path, duration, cmd.OutOrStdout(), cmd.ErrOrStderr())
	})
	serve.Flags().Duration("duration", 0, "optional observation duration before orderly shutdown")
	stop := installedCommand("stop", "Record STOPPED and verify portable runtime shutdown", func(cmd *cobra.Command, path string) error {
		if err := service.Stop(cmd.Context(), path); err != nil {
			return err
		}
		return printJSON(cmd, map[string]string{"state": "STOPPED"})
	})
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
	inspect := installedCommand("inspect-config", "Read the exact portable installation configuration", func(cmd *cobra.Command, path string) error {
		i, err := install.Open(path)
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(i.Manifest.Config)
		return errors.Join(err, i.Close())
	})
	update := installedCommand("update", "Approve a stopped backup and compatible portable binary update", func(cmd *cobra.Command, path string) error {
		m, err := install.Update(cmd.Context(), path, approval(cmd))
		return manifestResult(cmd, m, err)
	})
	approvalFlag(update)
	uninstall := installedCommand("uninstall", "Remove only installed portable code, retaining data", func(cmd *cobra.Command, path string) error {
		m, err := install.Uninstall(cmd.Context(), path)
		return manifestResult(cmd, m, err)
	})
	purge := installedCommand("purge", "Approve permanent deletion of this portable installation", func(cmd *cobra.Command, path string) error {
		if err := install.Purge(cmd.Context(), path, approval(cmd)); err != nil {
			return err
		}
		return printJSON(cmd, map[string]string{"state": "PURGED"})
	})
	approvalFlag(purge)
	rootCmd.AddCommand(doctor, initialize, prepareImageCommand(), generateConfigCommand(), configure, inspect, serve, stop, update, uninstall, purge)
	for _, name := range []string{"service", "_owner", "prepare-dev-worker", "discard-dev-revision", "inspect-dev-lock"} {
		rootCmd.AddCommand(&cobra.Command{Use: name, Hidden: true, DisableFlagParsing: true, RunE: func(_ *cobra.Command, _ []string) error { return install.ErrLegacy }})
	}
}

func installedCommand(name, summary string, run func(*cobra.Command, string) error) *cobra.Command {
	cmd := &cobra.Command{Use: name, Short: summary, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		path, err := install.Directory()
		if err != nil {
			return err
		}
		return run(cmd, path)
	}}
	cmd.SetFlagErrorFunc(legacyFlagError)
	return cmd
}

func legacyFlagError(_ *cobra.Command, err error) error {
	if name, ok := strings.CutPrefix(err.Error(), "unknown flag: --"); ok {
		switch name {
		case "archive-digest", "credential-file", "dev-mode", "dev-module-image", "dev-revision",
			"dev-socket", "draft", "entrypoint", "input", "job-id", "operator", "plan":
			return errors.Join(err, install.ErrLegacy)
		}
	}
	return err
}

func approvalFlag(cmd *cobra.Command) {
	cmd.Flags().StringArray("approve", nil, "exact displayed digest, repeated in approval order; otherwise read approval from stdin")
}

func approval(cmd *cobra.Command) install.Confirm {
	approved, _ := cmd.Flags().GetStringArray("approve")
	stdin := bufio.NewReader(io.LimitReader(cmd.InOrStdin(), 128<<10))
	return func(description string, value any, digest string) error {
		if err := json.NewEncoder(cmd.ErrOrStderr()).Encode(value); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "%s\nType %s to approve: ", description, digest); err != nil {
			return err
		}
		var received string
		if len(approved) > 0 {
			received, approved = approved[0], approved[1:]
		} else {
			var err error
			received, err = stdin.ReadString('\n')
			if err != nil && !(errors.Is(err, io.EOF) && received != "") {
				return errors.New("explicit approval required")
			}
		}
		if strings.TrimSpace(received) != digest {
			return errors.New("APPROVAL_MISMATCH: displayed digest was not approved")
		}
		_, err := fmt.Fprintln(cmd.ErrOrStderr())
		return err
	}
}


func manifestResult(cmd *cobra.Command, m install.Manifest, err error) error {
	if err != nil {
		return err
	}
	return printJSON(cmd, struct {
		PlanDigest string `json:"plan_digest"`
		ConfigPlan string `json:"config_plan_digest,omitempty"`
	}{m.State, m.PlanDigest, m.ConfigPlanDigest, m.Revision, len(m.Modules)})
}

func initialModuleRequested(cmd *cobra.Command) bool {
	for _, flag := range []string{"source-kind", "source", "digest", "registry-token-url", "registry-token-service", "registry-redirect-host", "limits-file", "module-id", "uid", "gid", "module-config", "approval", "network-profile"} {
		if cmd.Flags().Changed(flag) {
			return true
		}
	}
	return false
}

func prepareImageCommand() *cobra.Command {
	var read func() (install.ImageInput, error)
	command := installedCommand("prepare-image", "Stage an isolated, immutable image for separate module review", func(cmd *cobra.Command, path string) error {
		request, err := read()
		if err != nil {
			return err
		}
		g, err := install.PrepareImage(cmd.Context(), path, request, approval(cmd))
		if err != nil {
			return err
		}
		return printJSON(cmd, struct {
			SourceDigest string `json:"source_digest"`
		}{g.ID, "PREPARED", g.Digest, g.SourceDigest})
	})
	read = imageFlags(command)
	approvalFlag(command)
	return command
}

func imageFlags(command *cobra.Command) func() (install.ImageInput, error) {
	var source images.Source
	var sourceValue, limitsPath string
	flags := command.Flags()
	flags.StringVar(&source.Kind, "source-kind", "", "registry, oci-archive, or docker-archive")
	flags.StringVar(&sourceValue, "source", "", "HTTPS registry repository or canonical absolute archive path")
	flags.StringVar(&source.Digest, "digest", "", "exact source sha256 digest (complete archive bytes for offline sources)")
	flags.StringVar(&source.TokenURL, "registry-token-url", "", "optional exact approved HTTPS bearer token endpoint")
	flags.StringVar(&source.TokenService, "registry-token-service", "", "optional approved bearer token service")
	flags.StringArrayVar(&source.RedirectHosts, "registry-redirect-host", nil, "explicit additional approved registry content host (repeatable)")
	flags.StringVar(&limitsPath, "limits-file", "", "complete portable preparation limits JSON; deadline in nanoseconds")
	return func() (install.ImageInput, error) {
		request := install.ImageInput{Source: source, Limits: install.DefaultPreparationLimits()}
		if source.Kind == "registry" {
			request.Source.Reference = sourceValue
		} else {
			request.Archive = sourceValue
		}
		if limitsPath != "" {
			var err error
			request.Limits, err = readPreparationLimits(limitsPath)
			if err != nil {
				return install.ImageInput{}, err
			}
		}
		return request, nil
	}
}

func readPreparationLimits(path string) (images.Limits, error) {
	data, err := install.ReadInput(path)
	if err != nil {
		return images.Limits{}, err
	}
	var limits images.Limits
	if err := gvxcontract.DecodeStrict(data, 16<<10, 2, &limits); err != nil {
		return images.Limits{}, err
	}
	if err := limits.Validate(); err != nil {
		return images.Limits{}, err
	}
	return limits, nil
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
