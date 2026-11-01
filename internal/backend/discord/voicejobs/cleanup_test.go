package voicejobs

import (
	"context"
	"testing"
	"time"

	rt "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

type delayedCleanupTransport struct{ *fixtureTransport }

func (d delayedCleanupTransport) CloseContext(context.Context) error { return context.DeadlineExceeded }

func TestCleanupDeadlineNeverReleasesSenderOwnedBytesBeforeJoin(t *testing.T) {
	g, f, p := fixtureGuild(t)
	g.transport = delayedCleanupTransport{f}
	j := fixtureJob(t, g, p, "job", 1)
	acceptFixture(t, g, j, 1)
	sent := handoffFixture(t, g, f, j)
	receiptFixture(t, g, sent, context.DeadlineExceeded)
	g.onAbort(<-g.aborted)
	if !g.abortWaiting || g.inflight != j || g.service.usage.frames == 0 || terminal(j.snapshot.State) || f.leaves.Load() != 0 {
		t.Fatal("cleanup deadline released an unjoined sender owner")
	}
	// The fixture's cleanup owner, not a module or caller, proves real join now.
	_ = f.CloseContext(context.Background())
	g.cleanupJoined()
	if g.inflight != nil || g.service.usage.frames != 0 || j.snapshot.TerminalError.Reason != wire.VoiceErrorReason_VOICE_ERROR_REASON_CLEANUP_TIMEOUT {
		t.Fatal("joined cleanup did not resolve terminal ownership")
	}
	g.schedule()
	g.onDisconnect(<-g.closed)
	g.remove()
	if f.leaves.Load() != 1 || g.service.instances[p.InstanceID].usage.sessions != 0 {
		t.Fatal("last-reference disconnect/session accounting leaked")
	}
}
func TestClosingReservationKeepsInstanceSessionQuota(t *testing.T) {
	g, _, p := fixtureGuild(t)
	g.service.config.InstanceSessions = 1
	j := fixtureJob(t, g, p, "job", 1)
	g.stopJob(j, stopped(), true)
	other := &guild{service: g.service, id: "999", channel: "789", jobs: map[string]*job{}, subs: map[string]*subscription{}, owners: map[rt.InstanceID]int{}}
	g.service.guilds[other.id] = other
	if _, err := other.createJob(p, "next", &wire.CreatePlaybackJobRequest{Lifetime: durationpb.New(time.Hour)}); status.Code(err) != codes.ResourceExhausted {
		t.Fatal("closing generation escaped instance session quota")
	}
	g.schedule()
	g.onDisconnect(<-g.closed)
	g.remove()
	if _, err := other.createJob(p, "next", &wire.CreatePlaybackJobRequest{Lifetime: durationpb.New(time.Hour)}); err != nil {
		t.Fatal("joined closing reservation did not release quota")
	}
}
func TestUnpreparedCleanupDoesNotTouchForeignAdmission(t *testing.T) {
	c := fixtureConfig()
	c.FirstBindTimeout = time.Hour
	s, err := New(context.Background(), Options{Config: c, ResolveChannel: func(context.Context, rt.InstancePrincipal, string) (string, error) { return "123", nil }, Factory: func(context.Context, string, string, bool, bool) (Transport, error) {
		t.Error("cleanup unexpectedly started a foreign join")
		return nil, stopped()
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	p := rt.InstancePrincipal{ModuleID: "module", InstanceID: "owner"}
	if _, err = s.Register(rt.InstanceServices{Principal: p, Authorizer: new(rt.Authorizer), Limits: rt.Limits{ControlMessageMaxBytes: c.MaxGRPCMessageBytes}}); err != nil {
		t.Fatal(err)
	}
	foreign, err := s.actor("999", "789")
	if err != nil {
		t.Fatal(err)
	}
	foreign.releaseAdmission()
	if err = s.Cleanup(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err = s.Cleanup(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	select {
	case <-foreign.done:
		t.Fatal("instance cleanup closed another owner's pending admission")
	default:
	}
}
