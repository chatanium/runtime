package app

import (
	"context"
	"errors"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
)

type initialModuleManager interface {
	Launch(context.Context, runtime.ModuleSpec) (*runtime.Instance, error)
	ModuleSnapshot(runtime.ModuleID) (runtime.ModuleSnapshot, bool)
}

func activateInitialModules(ctx context.Context, manager initialModuleManager, modules []runtime.ModuleSpec, development bool) (observation, error) {
	out := observation{Phase: "RUNNING", Modules: len(modules), Voice: voiceEnabled}
	for _, spec := range modules {
		if _, err := manager.Launch(ctx, spec); err != nil {
			// Development control may repair a failed installed instance, but it
			// cannot invent one when validation failed before instance creation.
			if _, present := manager.ModuleSnapshot(spec.ModuleID); !development || !present {
				return observation{}, errors.New("module activation failed")
			}
			out.Phase = "DEVELOPMENT_DEGRADED"
		}
	}
	return out, nil
}
