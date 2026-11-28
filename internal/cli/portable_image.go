package cli

import (
	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/portable/images"
	"github.com/thirdscam/chatanium/internal/portable/install"
)

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
		if view, human := operatorOutput(cmd); human {
			if err := view.log(logInfo, "Image prepared for module review."); err != nil {
				return err
			}
			return view.detail("Image ID", g.ID)
		}
		return printJSON(cmd, struct {
			ID           string `json:"id"`
			State        string `json:"state"`
			Digest       string `json:"digest"`
			SourceDigest string `json:"source_digest"`
		}{g.ID, "PREPARED", g.Digest, g.SourceDigest})
	})
	read = imageFlags(command)
	approvalFlag(command)
	jsonOutputFlag(command)
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
