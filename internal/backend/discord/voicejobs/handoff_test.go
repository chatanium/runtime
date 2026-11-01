package voicejobs

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
	rt "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

type retiringPlaybackTransport struct {
	*fixtureTransport
	started, acknowledged chan struct{}
	ackOnce               sync.Once
}

func (v *retiringPlaybackTransport) acknowledge() {
	v.ackOnce.Do(func() { close(v.acknowledged) })
}
func (v *retiringPlaybackTransport) DisconnectContext(ctx context.Context) error {
	v.leaves.Add(1)
	_ = v.CloseContext(ctx)
	close(v.started)
	select {
	case <-v.acknowledged:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func retiringPlaybackGuild(t *testing.T) (*guild, *retiringPlaybackTransport, rt.InstancePrincipal) {
	t.Helper()
	g, f, p := fixtureGuild(t)
	v := &retiringPlaybackTransport{fixtureTransport: f, started: make(chan struct{}), acknowledged: make(chan struct{})}
	t.Cleanup(v.acknowledge)
	g.transport = v
	j := fixtureJob(t, g, p, "completed", 0)
	acceptFixture(t, g, j, 1)
	if err := g.accept(j, endInput(1)); err != nil {
		t.Fatal(err)
	}
	written := handoffFixture(t, g, f, j)
	receiptFixture(t, g, written, nil)
	g.schedule()
	if j.snapshot.State != wire.PlaybackState_PLAYBACK_STATE_COMPLETED {
		t.Fatal("prior playback did not complete")
	}
	g.schedule()
	select {
	case <-v.started:
	case <-time.After(time.Second):
		t.Fatal("last completed job did not start retirement")
	}
	return g, v, p
}

func TestPlaybackCreateQueuesBehindOwnRetiringConnection(t *testing.T) {
	g, old, p := retiringPlaybackGuild(t)
	// The retiring reference consumes the entire quota. Its same-owner handoff
	// must transfer that reference, not reserve an overlapping second session.
	g.service.config.InstanceSessions = 1
	next := newFixtureTransport()
	acquired := make(chan struct{}, 1)
	g.service.factory = func(context.Context, string, string, bool, bool) (Transport, error) {
		acquired <- struct{}{}
		return next, nil
	}
	// This is the exact owner-lane admission called by CreatePlaybackJob after
	// its existing target resolution and final authorization.
	snapshot, err := g.createJob(p, "next", &wire.CreatePlaybackJobRequest{Lifetime: durationpb.New(time.Hour)})
	if err != nil {
		t.Fatal("same-owner CreatePlaybackJob rejected its retiring connection")
	}
	if snapshot.State != wire.PlaybackState_PLAYBACK_STATE_QUEUED || snapshot.Reason != wire.PlaybackReason_PLAYBACK_REASON_WAITING_CONNECTION {
		t.Fatal("handoff admission did not queue for a connection")
	}
	j := g.jobs["next"]
	acceptFixture(t, g, j, 1)
	if err := g.accept(j, endInput(1)); err != nil {
		t.Fatal(err)
	}
	g.schedule()
	select {
	case <-acquired:
		t.Fatal("new connection acquired before old leave acknowledgement")
	default:
	}
	if g.inflight != nil || g.transport != old || g.service.instances[p.InstanceID].usage.sessions != 1 {
		t.Fatal("queued handoff overlapped transports or changed session quota")
	}
	old.acknowledge()
	g.onDisconnect(<-g.closed)
	g.schedule()
	var joined joinResult
	select {
	case joined = <-g.joined:
	case <-time.After(time.Second):
		t.Fatal("confirmed retirement did not acquire the queued connection")
	}
	if joined.err != nil || joined.transport != next {
		t.Fatal("queued handoff acquired an unexpected connection")
	}
	g.joining = false
	g.joinCancel()
	g.joinCancel = nil
	g.transport = joined.transport
	written := handoffFixture(t, g, next, j)
	receiptFixture(t, g, written, nil)
	g.schedule()
	if j.snapshot.State != wire.PlaybackState_PLAYBACK_STATE_COMPLETED || j.snapshot.LastUdpWrittenSequence != 1 || old.leaves.Load() != 1 {
		t.Fatal("queued job failed to complete after exactly one retirement")
	}
	g.schedule()
	g.onDisconnect(<-g.closed)
	g.remove()
	if g.service.instances[p.InstanceID].usage.sessions != 0 {
		t.Fatal("handoff leaked its transferred session quota")
	}
}

func TestPlaybackRetiringConnectionRejectsForeignOwnerAndTarget(t *testing.T) {
	g, old, p := retiringPlaybackGuild(t)
	foreign := rt.InstancePrincipal{ModuleID: "foreign", InstanceID: "foreign"}
	g.service.instances[foreign.InstanceID] = &instance{services: rt.InstanceServices{Principal: foreign}, active: true, ctx: g.ctx}
	request := &wire.CreatePlaybackJobRequest{Lifetime: durationpb.New(time.Hour)}
	if _, err := g.createJob(foreign, "foreign", request); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("retiring connection admitted a foreign owner")
	}
	if _, err := g.service.actor(g.id, "789"); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("retiring connection admitted a different target")
	}
	g.shutting = true
	if _, err := g.createJob(p, "shutdown", request); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("shutdown reopened a retiring connection")
	}
	g.shutting = false
	g.failAll(transportFailure(context.Canceled, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONNECTION))
	if _, err := g.createJob(p, "failed", request); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("failed retirement reopened its connection automatically")
	}
	old.acknowledge()
	g.onDisconnect(<-g.closed)
	g.remove()
}

func TestPlaybackQueuedHandoffFailsClosedOnRetirementFailure(t *testing.T) {
	g, old, p := retiringPlaybackGuild(t)
	if _, err := g.createJob(p, "next", &wire.CreatePlaybackJobRequest{Lifetime: durationpb.New(time.Hour)}); err != nil {
		t.Fatal("same-owner handoff admission failed")
	}
	j := g.jobs["next"]
	old.acknowledge()
	<-g.closed
	// Local Done alone cannot authorize replacement after a failed disconnect.
	g.onDisconnect(context.DeadlineExceeded)
	g.schedule()
	if j.snapshot.State != wire.PlaybackState_PLAYBACK_STATE_FAILED || j.snapshot.TerminalError == nil || j.snapshot.TerminalError.Reason != wire.VoiceErrorReason_VOICE_ERROR_REASON_CLEANUP_TIMEOUT || g.joining {
		t.Fatal("retirement failure left its queued job live or started replacement")
	}
	g.remove()
	if g.service.instances[p.InstanceID].usage.sessions != 0 {
		t.Fatal("failed handoff leaked its retained session quota")
	}
}

func TestPlaybackQueuedHandoffCancellationAndShutdownKeepRetirementOwned(t *testing.T) {
	for _, operation := range []string{"cancel", "owner-cleanup", "shutdown"} {
		t.Run(operation, func(t *testing.T) {
			g, old, p := retiringPlaybackGuild(t)
			if _, err := g.createJob(p, "next", &wire.CreatePlaybackJobRequest{Lifetime: durationpb.New(time.Hour)}); err != nil {
				t.Fatal("same-owner handoff admission failed")
			}
			j := g.jobs["next"]
			switch operation {
			case "shutdown":
				g.shutting = true
				g.failAll(stopped())
			case "owner-cleanup":
				g.service.instances[p.InstanceID].active = false
				g.service.instances[p.InstanceID].draining = true
				g.cleanupOwner(p)
			default:
				g.stopJob(j, stopped(), true)
			}
			g.schedule()
			if !terminal(j.snapshot.State) || g.joining || g.transport != old || g.closingOwner != p.InstanceID || g.service.instances[p.InstanceID].usage.sessions != 1 {
				t.Fatal("queued cancellation lost retiring ownership or reopened it")
			}
			old.acknowledge()
			g.onDisconnect(<-g.closed)
			g.schedule()
			if g.joining || g.transport != nil || !g.closeStarted {
				t.Fatal("canceled handoff acquired a replacement connection")
			}
			g.remove()
			if g.service.instances[p.InstanceID].usage.sessions != 0 {
				t.Fatal("canceled handoff leaked its retained session quota")
			}
		})
	}
}

func TestPlaybackAdmissionKeepsActorThroughCompletedRetirement(t *testing.T) {
	g, old, p := retiringPlaybackGuild(t)
	acquired, err := g.service.actor(g.id, g.channel)
	if err != nil || acquired != g {
		t.Fatal("same-target admission could not acquire its retiring actor")
	}
	old.acknowledge()
	g.onDisconnect(<-g.closed)
	// Model the actor's remove decision between the RPC's actor lookup and
	// its owner-lane admission command, without relying on scheduler timing.
	g.remove()
	g.service.mu.Lock()
	indexed := g.service.guilds[g.id] == g
	g.service.mu.Unlock()
	if !indexed {
		t.Fatal("retirement removed an actor acquired by a pending admission")
	}
	if _, err := g.createJob(p, "next", &wire.CreatePlaybackJobRequest{Lifetime: durationpb.New(time.Hour)}); err != nil {
		g.releaseAdmission()
		t.Fatal("pending admission failed after confirmed retirement")
	}
	g.releaseAdmission()
	if g.closing || g.closeStarted || g.transport != nil {
		t.Fatal("pending admission did not become eligible for fresh acquisition")
	}
	g.stopJob(g.jobs["next"], stopped(), true)
	g.remove()
}

func TestPlaybackAdmissionCancellationAndShutdownReleaseActorPin(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "shutdown"}[shutdown], func(t *testing.T) {
			g, old, p := retiringPlaybackGuild(t)
			acquired, err := g.service.actor(g.id, g.channel)
			if err != nil || acquired != g {
				t.Fatal("pending admission could not acquire its retiring actor")
			}
			old.acknowledge()
			g.onDisconnect(<-g.closed)
			if g.remove() {
				t.Fatal("retirement ignored an outstanding admission pin")
			}
			if shutdown {
				g.shutting = true
				g.service.instances[p.InstanceID].active = false
				g.service.instances[p.InstanceID].draining = true
				if _, err := g.createJob(p, "shutdown", &wire.CreatePlaybackJobRequest{Lifetime: durationpb.New(time.Hour)}); status.Code(err) != codes.FailedPrecondition {
					t.Fatal("shutdown admitted a pinned request")
				}
			} else {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if _, err := g.ask(ctx, func(g *guild) (any, error) {
					t.Error("canceled admission entered the owner lane")
					return g.createJob(p, "canceled", &wire.CreatePlaybackJobRequest{Lifetime: durationpb.New(time.Hour)})
				}); err != context.Canceled {
					t.Fatal("canceled admission did not return its context error")
				}
			}
			g.releaseAdmission()
			if !g.remove() || g.service.instances[p.InstanceID].usage.sessions != 0 {
				t.Fatal("canceled admission retained its actor pin or session quota")
			}
		})
	}
}

type delayedHandoffReceive struct {
	*fixtureTransport
	entered, release chan struct{}
	packet           *discordgo.Packet
	failure          error
}

func (v *delayedHandoffReceive) ReceiveOpus(ctx context.Context) (*discordgo.Packet, error) {
	close(v.entered)
	select {
	case <-v.release:
		return v.packet, v.failure
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestPlaybackRetirementDetachesLateReceiveFromReplacement(t *testing.T) {
	for _, packet := range []bool{false, true} {
		t.Run(map[bool]string{false: "failure", true: "packet"}[packet], func(t *testing.T) {
			g, old, p := retiringPlaybackGuild(t)
			oldPackets, oldFailures := g.received, g.receiveError
			delayed := &delayedHandoffReceive{fixtureTransport: old.fixtureTransport, entered: make(chan struct{}), release: make(chan struct{}), failure: context.Canceled}
			if packet {
				delayed.packet = &discordgo.Packet{Opus: []byte{1, 2, 3}}
				delayed.failure = nil
			}
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				g.receive(delayed, oldPackets, oldFailures)
			}()
			<-delayed.entered
			if _, err := g.createJob(p, "next", &wire.CreatePlaybackJobRequest{Lifetime: durationpb.New(time.Hour)}); err != nil {
				close(delayed.release)
				t.Fatal("same-owner handoff admission failed")
			}
			old.acknowledge()
			g.onDisconnect(<-g.closed)
			if g.received != nil || g.receiveError != nil {
				close(delayed.release)
				t.Fatal("retirement retained the old receive delivery lane")
			}
			g.received = make(chan *discordgo.Packet, 1)
			g.receiveError = make(chan error, 1)
			close(delayed.release)
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("old receive owner remained blocked after transport retirement")
			}
			select {
			case <-g.received:
				t.Fatal("old packet reached the replacement's receive lane")
			case <-g.receiveError:
				t.Fatal("old receive failure reached the replacement's error lane")
			default:
			}
			if packet {
				for _, b := range delayed.packet.Opus {
					if b != 0 {
						t.Fatal("abandoned old packet retained its owned bytes")
					}
				}
			} else {
				select {
				case <-oldFailures:
				default:
					t.Fatal("old failure did not remain on its own delivery lane")
				}
			}
			g.stopJob(g.jobs["next"], stopped(), true)
			g.remove()
		})
	}
}
