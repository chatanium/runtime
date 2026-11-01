package host

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestOriginalSandboxFailureSurvivesCleanupAndLateStartupWrites(t *testing.T) {
	f := newCreateStateFixture(t, EgressNone)
	ctx := context.Background()
	o := f.lease.Ownership
	p := &DockerPlatform{cfg: DockerConfig{APIDeadline: time.Second}, creates: f.journal}
	secret := "raw-module-or-daemon-content-must-not-be-journaled"
	err := p.recordFailure(o, PhaseAttach, classifiedFailure(FailureBootstrapMux, errors.New(secret)), FailureAttachRead)
	if failureReason(err, FailureInspect) != FailureBootstrapMux {
		t.Fatalf("original consumer classification lost: %v", err)
	}
	if err := f.journal.cleanup(ctx, o.InstanceID, false, errors.New(secret)); err != nil {
		t.Fatal(err)
	}
	// The main Start/Create path can finish after the collector noticed failure.
	if err := f.journal.container(ctx, f.lease, "known-container"); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.state(ctx, o.InstanceID, "STARTED", ""); err != nil {
		t.Fatal(err)
	}
	// A secondary poststart/cgroup failure must not replace the first cause.
	if err := f.journal.RecordFailure(ctx, o, PhasePoststart, FailureCgroupPids); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.cleanup(ctx, o.InstanceID, true, nil); err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	var state, reason, cleanup string
	if err := f.journal.db.QueryRowContext(ctx, "SELECT state,reason,cleanup FROM instances WHERE id=?", o.InstanceID).Scan(&state, &reason, &cleanup); err != nil {
		t.Fatal(err)
	}
	if state != "FAILED" || reason != "ATTACH:BOOTSTRAP_MULTIPLEX_REQUIRED" || cleanup != "COMPLETE" {
		t.Fatalf("original failure/cleanup independence lost: %s %s %s", state, reason, cleanup)
	}
	if strings.Contains(reason, secret) {
		t.Fatal("raw error text leaked into durable diagnostic")
	}
}

func TestCleanupDoesNotInventOriginalFailureAndCodesAreClosed(t *testing.T) {
	f := newCreateStateFixture(t, EgressNone)
	ctx := context.Background()
	o := f.lease.Ownership
	if err := f.journal.cleanup(ctx, o.InstanceID, false, ErrCleanupIncomplete); err != nil {
		t.Fatal(err)
	}
	var reason string
	if err := f.journal.db.QueryRowContext(ctx, "SELECT reason FROM instances WHERE id=?", o.InstanceID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "" {
		t.Fatalf("secondary cleanup became original failure: %q", reason)
	}
	if err := f.journal.RecordFailure(ctx, o, PhaseAttach, FailureReason("untrusted child text")); err == nil {
		t.Fatal("arbitrary diagnostic reason accepted")
	}
	if err := f.journal.RecordFailure(ctx, o, FailurePhase("untrusted phase"), FailureBootstrapEOF); err == nil {
		t.Fatal("arbitrary diagnostic phase accepted")
	}
	if err := f.journal.RecordFailure(ctx, o, PhaseAttach, FailureBootstrapEOF); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.db.QueryRowContext(ctx, "SELECT reason FROM instances WHERE id=?", o.InstanceID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "ATTACH:BOOTSTRAP_EOF" {
		t.Fatalf("original cause could not follow cleanup bookkeeping: %q", reason)
	}
}

func TestBootstrapDiagnosticsDistinguishProtocolSocketTLSAndMux(t *testing.T) {
	const base = "1|2|unix|/ipc/socket|grpc|not_base64!|true\n"
	for _, tc := range []struct {
		line string
		want FailureReason
	}{
		{"not a handshake\n", FailureBootstrapFormat},
		{strings.Replace(base, "1|2|", "1|1|", 1), FailureBootstrapProtocol},
		{strings.Replace(base, "|unix|", "|tcp|", 1), FailureBootstrapNetwork},
		{strings.Replace(base, "|true\n", "|false\n", 1), FailureBootstrapMux},
		{strings.Replace(base, "/ipc/socket", "/other/socket", 1), FailureBootstrapSocket},
		{base, FailureBootstrapTLS},
	} {
		_, err := validateDockerHandshake([]byte(tc.line), "/ipc")
		if err == nil || failureReason(err, FailureInspect) != tc.want {
			t.Fatalf("diagnostic for %q: %v, want %s", tc.line, err, tc.want)
		}
	}
}

func TestAttachDiagnosticsDistinguishFramingEOFAndTruncatedStream(t *testing.T) {
	invalid := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	shortFrame := make([]byte, 9)
	shortFrame[0] = 1
	binary.BigEndian.PutUint32(shortFrame[4:8], 2)
	for _, tc := range []struct {
		data []byte
		want FailureReason
	}{{nil, FailureBootstrapEOF}, {invalid, FailureAttachFrame}, {shortFrame, FailureAttachRead}} {
		// These failures happen before any writer is touched, so no host sink is
		// necessary to distinguish the actual framing/stream consumer behavior.
		err := collectDockerOutput(bytes.NewReader(tc.data), nil, nil, ResourceLimits{ControlMessageMaxBytes: 128, LogBufferBytes: 1 << 20}, "/ipc")
		if err == nil || failureReason(err, FailureInspect) != tc.want {
			t.Fatalf("attach diagnostic %v, want %s", err, tc.want)
		}
	}
}
