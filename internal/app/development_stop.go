//go:build linux

package app

import (
	"io"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
)

type developmentStopObservation struct {
	CleanupComplete bool              `json:"cleanup_complete"`
	CommittedImages map[string]string `json:"committed_images"`
}

type developmentModuleStop struct {
	failure         *stopFailureObservation
	cleanupComplete bool
}

func describeDevelopmentModuleStop(snapshot *runtime.InstanceSnapshot, err error) developmentModuleStop {
	return developmentModuleStop{
		failure:         describeStopFailure(snapshot, err),
		cleanupComplete: snapshot != nil && snapshot.CleanupComplete && snapshot.CleanupError == nil,
	}
}

type developmentSnapshotter interface {
	ModuleSnapshot(runtime.ModuleID) (runtime.ModuleSnapshot, bool)
}

// A receipt proves reclaimed resources, not logical module success. It is only
// eligible after the controller join and every non-module cleanup succeeded.
func emitDevelopmentStopped(output io.Writer, manager developmentSnapshotter, modules []runtime.ModuleSpec, stopped []developmentModuleStop, resourcesClean bool) error {
	if !resourcesClean || len(stopped) != len(modules) {
		return nil
	}
	for _, module := range stopped {
		if !module.cleanupComplete {
			return nil
		}
	}
	committed := make(map[string]string, len(modules))
	for _, spec := range modules {
		snapshot, present := manager.ModuleSnapshot(spec.ModuleID)
		if !present || !snapshot.CleanupComplete || snapshot.Reloading {
			return nil
		}
		if snapshot.CommittedImageDigest != "" {
			committed[string(spec.ModuleID)] = snapshot.CommittedImageDigest
		}
	}
	return emitObservation(output, observation{
		Phase: "DEVELOPMENT_STOPPED", Modules: len(modules), Voice: voiceEnabled,
		DevelopmentStop: &developmentStopObservation{CleanupComplete: true, CommittedImages: committed},
	})
}
