package install

import (
	"context"
	"errors"

	"github.com/thirdscam/chatanium/internal/portable/store"
)

// SetupForServe activates the observed INITIALIZING installation. It holds the
// owner lock across acquisition, candidate generation, and configuration review.
func SetupForServe(ctx context.Context, path string, m Manifest, first *FirstModule, confirm Confirm) error {
	_, err := activateInitial(ctx, path, m, first, "", confirm)
	return err
}

func activateInitial(ctx context.Context, path string, m Manifest, first *FirstModule, approvedImagePlan string, confirm Confirm) (_ Manifest, resultErr error) {
	if m.State != store.Initializing {
		return Manifest{}, store.ErrState
	}
	check := func(current *Manifest) error {
		if current.ID != m.ID {
			return store.ErrIdentity
		}
		if current.State != store.Initializing {
			return store.ErrState
		}
		if current.PlanDigest != m.PlanDigest || current.Bundle.Digest != m.Bundle.Digest || current.Revision != "" || len(current.Modules) != 0 {
			return store.ErrApprovalMismatch
		}
		return nil
	}
	i, err := lockPath(path, check)
	if err != nil {
		return Manifest{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, i.Close()) }()
	// The ordinary recovery pass can complete an earlier approved activation.
	if err := check(&i.Manifest); err != nil {
		return Manifest{}, err
	}
	if first == nil {
		return i.configure(ctx, Candidate{Format: Format, Config: i.Manifest.Config}, confirm)
	}
	options := first.Module
	if options.ImageID != "" || !modulePattern.MatchString(options.ModuleID) || options.UID == 0 || options.GID == 0 {
		return Manifest{}, errors.New("initial module requires its stable ID and nonroot guest UID/GID")
	}
	if err := i.verifyInitializationLedger(ctx); err != nil {
		return Manifest{}, err
	}
	generation, err := i.prepareImage(ctx, first.Image, confirm, m.PlanDigest, approvedImagePlan)
	if err != nil {
		return Manifest{}, err
	}
	options.ImageID = generation.ID
	candidate, err := i.generateConfig(options)
	if err != nil {
		return Manifest{}, err
	}
	return i.configure(ctx, candidate, confirm)
}
