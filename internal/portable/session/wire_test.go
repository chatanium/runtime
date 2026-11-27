package session

import (
	"bytes"
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thirdscam/chatanium/internal/discordacl"
	"github.com/thirdscam/chatanium/internal/host"
)

func TestWorkerInitKeepsApprovedBytes(t *testing.T) {
	credentials, err := NewCredentials("test-epoch")
	if err != nil {
		t.Fatal(err)
	}
	init := WorkerInit{Endpoint: filepath.Join(t.TempDir(), "ipc"), Credentials: credentials,
		Config: []byte("{\n \"foo\": 9007199254740993\n}\n"), Secrets: map[string]string{"discord:bot_token": "fixture"},
		DiscordACL: map[string]discordacl.Policy{"fixture": {}}}
	var frames bytes.Buffer
	if err = WriteWorkerInit(&frames, init); err != nil {
		t.Fatal(err)
	}
	if err = WriteWorkerACL(&frames, WorkerACLChange{ModuleID: "fixture", Revision: 9007199254740993}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Unix(123, 456)
	if err = WriteWorkerDrain(&frames, deadline); err != nil {
		t.Fatal(err)
	}
	got, err := ReadWorkerInit(&frames)
	if err != nil || got.Credentials != init.Credentials || !bytes.Equal(got.Config, init.Config) || got.Secrets["discord:bot_token"] != "fixture" {
		t.Fatal("worker INIT changed its approved configuration, epoch or captured bindings")
	}
	if _, ok := got.DiscordACL["fixture"]; !ok {
		t.Fatal("worker INIT omitted the Discord ACL snapshot")
	}
	change, err := ReadWorkerControl(&frames)
	if err != nil || !change.DrainDeadline.IsZero() ||
		change.ACLChange.ModuleID != "fixture" || change.ACLChange.Revision != 9007199254740993 {
		t.Fatalf("worker ACL change did not follow INIT: %+v (%v)", change, err)
	}
	if got, err := ReadWorkerControl(&frames); err != nil || !got.DrainDeadline.Equal(deadline) || got.ACLChange.ModuleID != "" || frames.Len() != 0 {
		t.Fatal("worker DRAIN did not follow the ACL update with an independent bounded frame")
	}
}

func TestWorkerControlRejectsAmbiguousACLFrames(t *testing.T) {
	deadline := time.Now()
	for _, control := range []workerControlFrame{
		{Type: "ACL_UPDATE", ModuleID: "fixture", Revision: 1},
		{Type: "ACL_UPDATE", ModuleID: "fixture", Revision: 0, Policy: &discordacl.Policy{}},
		{Type: "DRAIN", Deadline: &deadline, Policy: &discordacl.Policy{}},
	} {
		var frames bytes.Buffer
		if err := writeFrame(&frames, maxControlFrame, control); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadWorkerControl(&frames); !errors.Is(err, errProtocol) {
			t.Fatalf("malformed worker command accepted: %+v (%v)", control, err)
		}
	}
	var frames bytes.Buffer
	event := WorkerEvent{Type: "ACL_ACK", ACL: &WorkerACLAck{Revision: 1, Status: "UNKNOWN"}}
	if err := writeFrame(&frames, maxWorkerEvent, event); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWorkerEvent(&frames); !errors.Is(err, errProtocol) {
		t.Fatalf("unknown ACL acknowledgement status accepted: %v", err)
	}
}

type reconcileFixture struct {
	Backend
	n atomic.Int32
}

func (b *reconcileFixture) Reconcile(context.Context) error {
	b.n.Add(1)
	return nil
}

func TestSessionAuthenticationRejectsStaleEpochAndWrongToken(t *testing.T) {
	current, err := NewCredentials("current-epoch")
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewCredentials(current.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newAuthentication(current)
	if err != nil {
		t.Fatal(err)
	}
	backend := new(reconcileFixture)
	for _, tc := range []struct {
		name        string
		credentials Credentials
		allow       bool
	}{
		{"wrong-token", other, false},
		{"stale-epoch", Credentials{Epoch: "stale--epoch", Token: current.Token}, false},
		{"current", current, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth, err := newAuthentication(tc.credentials)
			if err != nil {
				t.Fatal(err)
			}
			before := backend.n.Load()
			c, s := net.Pipe()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			done := make(chan struct{})
			go func() {
				defer close(done)
				serveCall(t.Context(), s, server, backend)
			}()
			defer func() { _ = c.Close(); <-done }()
			err = auth.authenticate(c, true)
			if (err == nil) != tc.allow {
				t.Fatalf("unexpected authenticated session: %v", err)
			}
			if !tc.allow {
				if backend.n.Load() != before {
					t.Fatal("stale or untrusted worker caused a backend operation")
				}
				return
			}
			if err = writeFrame(c, maxRequestBytes, request{Op: reconcile}); err != nil {
				t.Fatal(err)
			}
			var r response
			if err = readFrame(c, maxRPCBytes, &r); err != nil || r.Error != "" || !r.valid(reconcile) || backend.n.Load() != before+1 {
				t.Fatalf("authenticated worker did not dispatch exactly once: %+v %v", r, err)
			}
		})
	}
}

func TestCleanupPendingSurvivesContextErrorAndRedactsDetails(t *testing.T) {
	local := errors.Join(context.DeadlineExceeded, &host.Error{Reason: "CLEANUP_INCOMPLETE", Message: "private host diagnostic"})
	public := remoteError(wireError(local))
	var typed *host.Error
	if !errors.Is(public, host.ErrCleanupIncomplete) || !errors.As(public, &typed) || typed.Reason != "CLEANUP_INCOMPLETE" || typed.Message == "private host diagnostic" {
		t.Fatalf("cleanup classification was obscured or private details crossed the worker protocol: %v", public)
	}
}
