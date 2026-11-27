//go:build linux

package host

import (
	"errors"
	"math"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/thirdscam/chatanium/internal/bundle"
)

func TestGvxSystemdFiniteCeilings(t *testing.T) {
	good := ResourceLimits{NanoCPUs: 1500000000, MemoryBytes: 64 << 20, Pids: 128}
	quota, e := finiteLimits(good)
	if e != nil || quota != 1500000 {
		t.Fatalf("quota=%d, error=%v", quota, e)
	}
	for _, change := range []func(*ResourceLimits){func(r *ResourceLimits) { r.NanoCPUs = 0 }, func(r *ResourceLimits) { r.NanoCPUs = 10000001 }, func(r *ResourceLimits) { r.NanoCPUs = 1500001000 }, func(r *ResourceLimits) { r.NanoCPUs = math.MaxInt64 }, func(r *ResourceLimits) { r.MemoryBytes++ }, func(r *ResourceLimits) { r.Pids = math.MaxInt64 }, func(r *ResourceLimits) { r.Pids = 0 }} {
		r := good
		change(&r)
		if _, e = finiteLimits(r); e == nil {
			t.Fatalf("unrepresentable ceiling accepted: %+v", r)
		}
	}
}
func TestGvxSystemdNativeTerminalEvidence(t *testing.T) {
	for _, tc := range []struct {
		observation UnitObservation
		want        ProcessExit
		valid       bool
	}{
		{UnitObservation{ExecMainCode: 1, ExecMainStatus: 0}, ProcessExit{Kind: "exit"}, true},
		{UnitObservation{ExecMainCode: 2, ExecMainStatus: 9, Result: "oom-kill"}, ProcessExit{Kind: "signal", Value: 9, OOMKilled: true}, true},
		{UnitObservation{ExecMainCode: 3, ExecMainStatus: 11}, ProcessExit{Kind: "signal", Value: 11}, true},
		{UnitObservation{ExecMainCode: 0, Result: "success"}, ProcessExit{}, false},
		{UnitObservation{ExecMainCode: 1, ExecMainStatus: 256}, ProcessExit{}, false},
		{UnitObservation{ExecMainCode: 2, ExecMainStatus: 0}, ProcessExit{}, false},
	} {
		got, e := nativeExit(tc.observation)
		if tc.valid && (e != nil || got != tc.want) || !tc.valid && e == nil {
			t.Fatalf("nativeExit(%+v)=%+v,%v", tc.observation, got, e)
		}
	}
}
func TestGvxSystemdSubmissionUncertainty(t *testing.T) {
	for _, e := range []error{errors.New("transport closed"), errors.New("context deadline exceeded"), dbus.Error{Name: "org.freedesktop.DBus.Error.NoReply"}, dbus.Error{Name: systemdInterface + ".NoSuchUnit"}} {
		if got := systemdRejection(e); got != "" {
			t.Fatalf("uncertain outcome became rejection: %v", e)
		}
	}
	if systemdRejection(dbus.Error{Name: "org.freedesktop.DBus.Error.InvalidArgs"}) == "" {
		t.Fatal("completed authoritative rejection retained as uncertain")
	}
}
func TestGvxSystemdClosedPurposeAuthority(t *testing.T) {
	for _, id := range []bundle.ProgramID{bundle.Worker, bundle.Stage, bundle.Preparer} {
		if _, e := purposePolicy(OwnedService{Program: id}); e == nil {
			t.Fatalf("root identity accepted for %s", id)
		}
		if caps, e := purposePolicy(OwnedService{Program: id, Identity: NumericIdentity{UID: 1000, GID: 1000}}); e != nil || caps != 0 {
			t.Fatalf("nonroot role=%s caps=%x err=%v", id, caps, e)
		}
	}
	good := []string{"useradd", "--system", "--uid", "1000", "--gid", "1000", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "chatanium_app"}
	if e := validateAccountCommand(bundle.ProgramID("useradd"), good); e != nil {
		t.Fatal(e)
	}
	if e := validateAccountCommand(bundle.ProgramID("useradd"), append(good, "--create-home")); e == nil {
		t.Fatal("extra account authority accepted")
	}
	if e := validateAccountCommand(bundle.ProgramID("userdel"), []string{"userdel", "--remove", "chatanium_app"}); e == nil {
		t.Fatal("home-removing purge accepted")
	}
}
