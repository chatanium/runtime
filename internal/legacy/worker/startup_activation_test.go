//go:build linux

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/thirdscam/chatanium/internal/app"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
)

type initialModuleFixture struct {
	failure  runtime.ModuleID
	missing  bool
	launched []runtime.ModuleID
	states   map[runtime.ModuleID]runtime.ModuleSnapshot
}

func (manager *initialModuleFixture) Launch(_ context.Context, spec runtime.ModuleSpec) (*runtime.Instance, error) {
	manager.launched = append(manager.launched, spec.ModuleID)
	snapshot := runtime.ModuleSnapshot{Principal: runtime.InstancePrincipal{ModuleID: spec.ModuleID, InstanceID: "initial"}, State: runtime.Running}
	if spec.ModuleID == manager.failure {
		if !manager.missing {
			snapshot.State = runtime.Failed
			manager.states[spec.ModuleID] = snapshot
		}
		return nil, errors.New("private activation diagnostic")
	}
	manager.states[spec.ModuleID] = snapshot
	return nil, nil
}

func (manager *initialModuleFixture) ModuleSnapshot(id runtime.ModuleID) (runtime.ModuleSnapshot, bool) {
	snapshot, ok := manager.states[id]
	return snapshot, ok
}

func TestStartupActivationObservationReflectsDevelopmentRecovery(t *testing.T) {
	modules := []runtime.ModuleSpec{{ModuleID: "first"}, {ModuleID: "second"}}
	for _, test := range []struct {
		name         string
		development  bool
		failure      runtime.ModuleID
		missing      bool
		wantPhase    string
		wantLaunches int
	}{
		{name: "healthy production", wantPhase: "RUNNING", wantLaunches: 2},
		{name: "healthy development", development: true, wantPhase: "RUNNING", wantLaunches: 2},
		{name: "development recovery remains available", development: true, failure: "first", wantPhase: "DEVELOPMENT_DEGRADED", wantLaunches: 2},
		{name: "later development failure is degraded", development: true, failure: "second", wantPhase: "DEVELOPMENT_DEGRADED", wantLaunches: 2},
		{name: "production failure stops activation", failure: "first", wantLaunches: 1},
		{name: "development cannot recover absent instance", development: true, failure: "first", missing: true, wantLaunches: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := &initialModuleFixture{failure: test.failure, missing: test.missing, states: make(map[runtime.ModuleID]runtime.ModuleSnapshot)}
			out, err := activateInitialModules(context.Background(), manager, modules, test.development)
			if len(manager.launched) != test.wantLaunches {
				t.Fatal("startup did not preserve production rejection or development recovery")
			}
			if test.wantPhase == "" {
				if err == nil || out.Phase != "" || bytes.Contains([]byte(err.Error()), []byte("private activation diagnostic")) {
					t.Fatal("rejected activation advertised readiness or leaked diagnostics")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := emitObservation(&output, out); err != nil {
				t.Fatal(err)
			}
			var emitted observation
			if err := json.Unmarshal(output.Bytes(), &emitted); err != nil {
				t.Fatal(err)
			}
			if emitted.Phase != test.wantPhase || emitted.Modules != len(modules) || emitted.Voice != app.VoiceEnabled || bytes.Contains(output.Bytes(), []byte("private activation diagnostic")) {
				t.Fatal("emitted startup observation misrepresented activation state")
			}
			if test.failure != "" {
				snapshot, present := manager.ModuleSnapshot(test.failure)
				if !present || snapshot.State != runtime.Failed {
					t.Fatal("degraded readiness did not retain the failed instance for explicit reload")
				}
			}
		})
	}
}
