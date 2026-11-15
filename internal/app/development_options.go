package app

import (
	"errors"
	"strings"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
)

func validateDevelopmentOptions(options StartOptions) error {
	if !options.DevelopmentMode {
		if options.DevelopmentSocket != "" || len(options.DevelopmentImages) != 0 {
			return errors.New("development options require explicit development mode")
		}
		return nil
	}
	if !canonicalPath(options.DevelopmentSocket) {
		return errors.New("development mode requires a canonical absolute private socket")
	}
	return nil
}

// Only the image field in this freshly decoded in-memory configuration changes.
// Approval, configuration, identity and the installed operator file are untouched.
func applyDevelopmentImages(config *runtime.Config, images []string) error {
	if len(images) == 0 {
		return nil
	}
	updates := make(map[runtime.ModuleID]string, len(images))
	for _, override := range images {
		id, image, ok := strings.Cut(override, "=")
		if !ok || id == "" || image == "" {
			return errors.New("invalid development image override")
		}
		moduleID := runtime.ModuleID(id)
		if _, duplicate := updates[moduleID]; duplicate {
			return errors.New("duplicate development image override")
		}
		found := false
		for _, spec := range config.Modules {
			if spec.ModuleID != moduleID {
				continue
			}
			currentRepository, _, _ := strings.Cut(spec.ImageDigest, "@")
			repository, digest, immutable := strings.Cut(image, "@sha256:")
			if !immutable || repository != currentRepository || len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" {
				return errors.New("development override requires an immutable image in the installed repository")
			}
			found = true
			break
		}
		if !found {
			return errors.New("development override module is not installed")
		}
		updates[moduleID] = image
	}
	for index := range config.Modules {
		if image, ok := updates[config.Modules[index].ModuleID]; ok {
			config.Modules[index].ImageDigest = image
		}
	}
	return nil
}
