package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
)

type developmentStopSnapshots map[runtime.ModuleID]runtime.ModuleSnapshot

func (snapshots developmentStopSnapshots) ModuleSnapshot(id runtime.ModuleID) (runtime.ModuleSnapshot, bool) {
	snapshot, present := snapshots[id]
	return snapshot, present
}

func TestDevelopmentStoppedReceiptSeparatesLogicalFailureFromCleanup(t *testing.T) {
	committed := "registry.test/team/module@sha256:" + strings.Repeat("1", 64)
	candidate := "registry.test/team/module@sha256:" + strings.Repeat("2", 64)
	instance := &runtime.InstanceSnapshot{
		Principal: runtime.InstancePrincipal{ModuleID: "module", InstanceID: runtime.InstanceID(strings.Repeat("a", 32))},
		State:     runtime.Failed, FailureReason: "HOOK_FAILED", CleanupComplete: true,
	}
	stopped := describeDevelopmentModuleStop(instance, nil)
	if stopped.failure == nil || stopped.failure.State != "FAILED" || !stopped.cleanupComplete {
		t.Fatal("reclaimed logical failure was suppressed or treated as uncertain cleanup")
	}
	manager := developmentStopSnapshots{"module": {
		Principal: instance.Principal, ImageDigest: candidate, CommittedImageDigest: committed,
		State: runtime.Failed, CleanupComplete: true,
	}}
	var output bytes.Buffer
	if err := emitObservation(&output, observation{Phase: "STOP_FAILED", Modules: 1, Voice: voiceEnabled, StopFailure: stopped.failure}); err != nil {
		t.Fatal(err)
	}
	if err := emitDevelopmentStopped(&output, manager, []runtime.ModuleSpec{{ModuleID: "module"}}, []developmentModuleStop{stopped}, true); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	var failure, receipt observation
	if decoder.Decode(&failure) != nil || decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF {
		t.Fatal("shutdown did not retain truthful failure followed by a final cleanup receipt")
	}
	if failure.Phase != "STOP_FAILED" || failure.StopFailure == nil || failure.StopFailure.State != "FAILED" {
		t.Fatal("positive cleanup proof erased the logical module failure")
	}
	if receipt.Phase != "DEVELOPMENT_STOPPED" || receipt.Modules != 1 || receipt.Voice != voiceEnabled || receipt.DevelopmentStop == nil || !receipt.DevelopmentStop.CleanupComplete || receipt.DevelopmentStop.CommittedImages["module"] != committed || len(receipt.DevelopmentStop.CommittedImages) != 1 {
		t.Fatal("final receipt did not prove cleanup and preserve the last successful image")
	}
	if stopped.failure == nil {
		t.Fatal("positive cleanup receipt cleared the failure used by the runtime exit result")
	}
}

func TestDevelopmentStoppedReceiptRejectsUncertainCleanup(t *testing.T) {
	for _, test := range []struct {
		name            string
		instance        *runtime.InstanceSnapshot
		stopErr         error
		resourcesClean  bool
		missingStop     bool
		missingSnapshot bool
		reloading       bool
		liveIncomplete  bool
	}{
		{name: "cleanup error", instance: &runtime.InstanceSnapshot{State: runtime.Failed, CleanupComplete: true, CleanupError: errors.New("private cleanup diagnostic")}, resourcesClean: true},
		{name: "incomplete cleanup", instance: &runtime.InstanceSnapshot{State: runtime.Failed}, resourcesClean: true},
		{name: "no instance", stopErr: errors.New("private stop diagnostic"), resourcesClean: true},
		{name: "nonmodule cleanup failed", instance: &runtime.InstanceSnapshot{State: runtime.Stopped, CleanupComplete: true}},
		{name: "production or incomplete startup", instance: &runtime.InstanceSnapshot{State: runtime.Stopped, CleanupComplete: true}},
		{name: "missing stop join", instance: &runtime.InstanceSnapshot{State: runtime.Stopped, CleanupComplete: true}, resourcesClean: true, missingStop: true},
		{name: "missing current snapshot", instance: &runtime.InstanceSnapshot{State: runtime.Stopped, CleanupComplete: true}, resourcesClean: true, missingSnapshot: true},
		{name: "reload not joined", instance: &runtime.InstanceSnapshot{State: runtime.Stopped, CleanupComplete: true}, resourcesClean: true, reloading: true},
		{name: "current cleanup incomplete", instance: &runtime.InstanceSnapshot{State: runtime.Stopped, CleanupComplete: true}, resourcesClean: true, liveIncomplete: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := developmentStopSnapshots{}
			if !test.missingSnapshot {
				manager["module"] = runtime.ModuleSnapshot{CleanupComplete: !test.liveIncomplete, Reloading: test.reloading}
			}
			var stops []developmentModuleStop
			if !test.missingStop {
				stops = append(stops, describeDevelopmentModuleStop(test.instance, test.stopErr))
			}
			var output bytes.Buffer
			if err := emitDevelopmentStopped(&output, manager, []runtime.ModuleSpec{{ModuleID: "module"}}, stops, test.resourcesClean); err != nil {
				t.Fatal(err)
			}
			if output.Len() != 0 {
				t.Fatal("uncertain cleanup produced an affirmative development receipt")
			}
		})
	}
}

func TestDevelopmentStoppedReceiptOmitsUncommittedImagesAndFailsClosedOnOutput(t *testing.T) {
	modules := []runtime.ModuleSpec{{ModuleID: "module"}}
	manager := developmentStopSnapshots{"module": {State: runtime.Failed, CleanupComplete: true}}
	stops := []developmentModuleStop{describeDevelopmentModuleStop(&runtime.InstanceSnapshot{State: runtime.Failed, CleanupComplete: true}, nil)}
	var output bytes.Buffer
	if err := emitDevelopmentStopped(&output, manager, modules, stops, true); err != nil {
		t.Fatal(err)
	}
	var receipt observation
	if json.Unmarshal(output.Bytes(), &receipt) != nil || receipt.DevelopmentStop == nil || receipt.DevelopmentStop.CommittedImages == nil || len(receipt.DevelopmentStop.CommittedImages) != 0 {
		t.Fatal("never-successful image was advertised as a committed image")
	}
	if err := emitDevelopmentStopped(failedReconciliationWriter{}, manager, modules, stops, true); err == nil || errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("failed receipt output was accepted or exposed a raw writer error")
	}
}

func TestDevelopmentRecordDistinguishesFailedCandidateFromCommittedImage(t *testing.T) {
	snapshot := runtime.ModuleSnapshot{ImageDigest: "failed-candidate", CommittedImageDigest: "successful-image", State: runtime.Failed}
	record := developmentRecord(snapshot)
	if record.Image != snapshot.ImageDigest || record.CommittedImage != snapshot.CommittedImageDigest || record.State != runtime.Failed {
		t.Fatal("control snapshot conflated a failed image attempt with the committed image")
	}
}
