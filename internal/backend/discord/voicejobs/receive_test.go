package voicejobs

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
	rt "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func fixtureSub(g *guild, p rt.InstancePrincipal, id string) *subscription {
	s := g.service
	i := s.instances[p.InstanceID]
	s.usage.subs++
	i.usage.subs++
	if g.owners[p.InstanceID] == 0 {
		i.usage.sessions++
	}
	g.owners[p.InstanceID]++
	v := &subscription{id: id, owner: p, snapshot: &wire.VoiceSubscriptionSnapshot{SubscriptionId: id, GuildId: g.id, ChannelId: g.channel, State: wire.VoiceSubscriptionState_VOICE_SUBSCRIPTION_STATE_ACTIVE, ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))}, events: make(chan *wire.VoiceReceiveEvent, s.config.SubscriptionPackets+2), released: make(chan struct{}), deliveryActive: true}
	v.header = readyEvent(&wire.VoiceSubscriptionSnapshot{SubscriptionId: id, State: wire.VoiceSubscriptionState_VOICE_SUBSCRIPTION_STATE_JOINING})
	g.subs[id] = v
	s.subs[id] = &subRef{owner: p, guild: g.id, channel: g.channel, actor: g}
	g.initialized = true
	return v
}
func TestReceiveFanoutHasDistinctImmutableEnvelopes(t *testing.T) {
	g, _, p := fixtureGuild(t)
	a, b := fixtureSub(g, p, "a"), fixtureSub(g, p, "b")
	packet := &discordgo.Packet{SSRC: 7, Sequence: 8, Timestamp: 9, Opus: []byte{0xf8, 0xff, 0xfe}}
	g.fanout(packet)
	first, second := <-a.events, <-b.events
	if first == second || first.GetPacket() == second.GetPacket() {
		t.Fatal("shared mutable protobuf envelope")
	}
	if first.GetPacket().SubscriptionId != "a" || second.GetPacket().SubscriptionId != "b" {
		t.Fatal("subscription identity mixed")
	}
	if &first.GetPacket().Opus[0] != &second.GetPacket().Opus[0] {
		t.Fatal("immutable owned payload was unnecessarily copied per receiver")
	}
	g.ackSub(a, first)
	g.ackSub(b, second)
	if g.service.receivePackets != 0 || g.service.receiveBytes != 0 {
		t.Fatal("delivered packet accounting leaked")
	}
}
func TestSlowConsumerFailsOnlyItself(t *testing.T) {
	g, _, p := fixtureGuild(t)
	slow, normal := fixtureSub(g, p, "slow"), fixtureSub(g, p, "normal")
	var saved *wire.VoicePacket
	for n := range 3 {
		g.fanout(&discordgo.Packet{SSRC: 7, Sequence: uint16(n), Opus: []byte{0xf8, 0xff, byte(n)}})
		event := <-normal.events
		if event.GetPacket() == nil {
			t.Fatal("healthy consumer terminated")
		}
		if n == 0 {
			saved = event.GetPacket()
		}
		g.ackSub(normal, event)
	}
	if !slow.terminal || normal.terminal || slow.snapshot.TerminalError.Reason != wire.VoiceErrorReason_VOICE_ERROR_REASON_RECEIVE_OVERFLOW {
		t.Fatal("overflow was not isolated")
	}
	if saved.SubscriptionId != "normal" || !reflect.DeepEqual(saved.Opus, []byte{0xf8, 0xff, 0}) {
		t.Fatal("another subscription changed a delivered packet")
	}
	terminal := <-slow.events
	if terminal.GetTerminal() == nil {
		t.Fatal("overflow silently became packet loss")
	}
	g.releaseSub(slow)
	g.releaseSub(slow)
	if g.service.usage.subs != 1 {
		t.Fatal("repeat release touched another subscriber")
	}
}
func TestReceiveFilterAndActiveDeliveryGate(t *testing.T) {
	g, _, p := fixtureGuild(t)
	v := fixtureSub(g, p, "receive")
	v.deliveryActive = false
	v.filters = map[uint32]struct{}{1: {}}
	g.fanout(&discordgo.Packet{SSRC: 1, Opus: []byte{1}})
	if len(v.events) != 0 {
		t.Fatal("packet preceded ACTIVE delivery")
	}
	g.ackSub(v, readyEvent(v.snapshot))
	g.fanout(&discordgo.Packet{SSRC: 2, Opus: []byte{1}})
	if len(v.events) != 0 {
		t.Fatal("SSRC filter ignored")
	}
	g.fanout(&discordgo.Packet{SSRC: 1, Opus: []byte{1}})
	if len(v.events) != 1 {
		t.Fatal("matching packet was lost")
	}
}
func TestJobAndReceiveReservationsAreIndependent(t *testing.T) {
	g, f, p := fixtureGuild(t)
	j := fixtureJob(t, g, p, "job", 1)
	v := fixtureSub(g, p, "receive")
	g.finishSub(v, nil)
	g.releaseSub(v)
	scheduleFixture(t, g)
	if g.closing || g.closeStarted {
		t.Fatal("last receiver disconnected a remaining job")
	}
	v = fixtureSub(g, p, "remaining")
	g.stopJob(j, stopped(), true)
	scheduleFixture(t, g)
	if g.closing || g.closeStarted {
		t.Fatal("last job disconnected receive-only owner")
	}
	g.finishSub(v, nil)
	g.releaseSub(v)
	scheduleFixture(t, g)
	if !g.closeStarted {
		t.Fatal("empty guild transport not closed")
	}
	if err := <-g.closed; err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.done:
	default:
		t.Fatal("real close seam not invoked")
	}
}
func TestPausedAndReceiveOnlyChannelsConflict(t *testing.T) {
	g, _, p := fixtureGuild(t)
	j := fixtureJob(t, g, p, "job", 1)
	j.paused = true
	if _, err := g.service.actor(g.id, "789"); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("paused reservation could be moved")
	}
	g.stopJob(j, stopped(), true)
	fixtureSub(g, p, "receive")
	if _, err := g.service.actor(g.id, "789"); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("receive-only reservation could be moved")
	}
}
func TestCrashCleanupDoesNotCancelAnotherOwner(t *testing.T) {
	g, _, p := fixtureGuild(t)
	other := rt.InstancePrincipal{ModuleID: "other", InstanceID: "other"}
	ctx, cancel := context.WithCancel(g.ctx)
	defer cancel()
	g.service.instances[other.InstanceID] = &instance{services: rt.InstanceServices{Principal: other}, active: true, ctx: ctx, cancel: cancel}
	mine := fixtureJob(t, g, p, "mine", 1)
	theirs := fixtureJob(t, g, other, "theirs", 2)
	receive := fixtureSub(g, other, "receive")
	g.cleanupOwner(p)
	g.cleanupOwner(p)
	if mine.snapshot.State != wire.PlaybackState_PLAYBACK_STATE_CANCELLED || g.jobs[theirs.id] != theirs || receive.terminal || g.service.usage.jobs != 1 {
		t.Fatal("one crash damaged a peer owner")
	}
	g.schedule()
	if g.closing {
		t.Fatal("peer references were not preserved")
	}
}
func TestReceiveExpiryAndSlowDeadlineAreExplicit(t *testing.T) {
	g, _, p := fixtureGuild(t)
	v := fixtureSub(g, p, "expired")
	v.snapshot.ExpiresAt = timestamppb.New(time.Unix(10, 0))
	g.expire(time.Unix(11, 0))
	if !v.terminal || v.snapshot.TerminalError.Reason != wire.VoiceErrorReason_VOICE_ERROR_REASON_LIFETIME_EXCEEDED {
		t.Fatal("receive lifetime escaped")
	}
	g.releaseSub(v)
	g, _, p = fixtureGuild(t)
	v = fixtureSub(g, p, "slow")
	v.pendingSince = time.Unix(10, 0)
	g.expire(time.Unix(10, 0).Add(2 * g.service.config.SlowConsumerTimeout))
	if !v.terminal || v.snapshot.TerminalError.Reason != wire.VoiceErrorReason_VOICE_ERROR_REASON_RECEIVE_TIMEOUT {
		t.Fatal("slow receiver not failed")
	}
	g.expire(v.pendingSince.Add(2 * g.service.config.SlowConsumerTimeout))
	if _, ok := g.subs[v.id]; ok {
		t.Fatal("terminal reader retained resources indefinitely")
	}
}
func TestUnsubscribeWaitsForSoleWriterRelease(t *testing.T) {
	g, _, p := fixtureGuild(t)
	v := fixtureSub(g, p, "receive")
	waiter := make(chan answer, 1)
	v.waiters = append(v.waiters, waiter)
	g.finishSub(v, nil)
	select {
	case <-waiter:
		t.Fatal("unsubscribe completed before writer cleanup")
	default:
	}
	g.releaseSub(v)
	result := <-waiter
	if result.value.(*wire.VoiceSubscriptionSnapshot).State != wire.VoiceSubscriptionState_VOICE_SUBSCRIPTION_STATE_CLOSED {
		t.Fatal("wrong terminal unsubscribe result")
	}
}
func TestConcurrentControlCleanupIsSerialized(t *testing.T) {
	g, _, p := fixtureGuild(t)
	j := fixtureJob(t, g, p, "job", 1)
	go g.run()
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			_ = g.call(context.Background(), func(g *guild) (any, error) {
				if active := g.jobs[j.id]; active != nil {
					g.stopJob(active, stopped(), true)
				}
				return nil, nil
			})
		})
	}
	wg.Wait()
	<-g.done
	g.releaseStatus(j)
	if g.service.usage.jobs != 0 || g.service.usage.frames != 0 || g.service.usage.bytes != 0 || len(g.service.guilds) != 0 {
		t.Fatal("concurrent cleanup leaked or double released resources")
	}
}
func TestOneJoinPerGenerationAndCreationContextDetached(t *testing.T) {
	c := fixtureConfig()
	c.ConnectionTimeout = time.Hour
	c.FirstBindTimeout = time.Hour
	var joins atomic.Int32
	started := make(chan struct{}, 1)
	s, err := New(context.Background(), Options{Config: c, ResolveChannel: func(context.Context, rt.InstancePrincipal, string) (string, error) { return "123", nil }, Factory: func(ctx context.Context, guild, channel string, mute, deaf bool) (Transport, error) {
		joins.Add(1)
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
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
	life, cancelLife := context.WithCancel(s.ctx)
	defer cancelLife()
	s.mu.Lock()
	s.instances[p.InstanceID] = &instance{services: rt.InstanceServices{Principal: p}, active: true, ctx: life, cancel: cancelLife}
	s.mu.Unlock()
	g, err := s.actor("123", "456")
	if err != nil {
		t.Fatal(err)
	}
	create, cancelCreate := context.WithCancel(context.Background())
	_, err = g.ask(create, func(g *guild) (any, error) {
		return g.createJob(p, "a", &wire.CreatePlaybackJobRequest{Lifetime: durationpb.New(time.Hour)})
	})
	g.releaseAdmission()
	if err != nil {
		t.Fatal(err)
	}
	cancelCreate()
	<-started
	_, err = g.ask(context.Background(), func(g *guild) (any, error) {
		if terminal(g.jobs["a"].snapshot.State) {
			return nil, errors.New("creation context ended persistent job")
		}
		_, e := g.createJob(p, "b", &wire.CreatePlaybackJobRequest{Lifetime: durationpb.New(time.Hour)})
		return nil, e
	})
	if err != nil {
		t.Fatal(err)
	}
	if joins.Load() != 1 {
		t.Fatal("ensure join duplicated a generation")
	}
	if err := s.Cleanup(context.Background(), p); err != nil {
		t.Fatal(err)
	}
}
func TestNotReadyBeforeHandoffRetainsUnsubmittedFrame(t *testing.T) {
	g, _, p := fixtureGuild(t)
	j := fixtureJob(t, g, p, "job", 1)
	acceptFixture(t, g, j, 1)
	g.inflight = j
	g.inflightFrame = j.frames.pop()
	g.handed = false
	g.onSend(sendResult{j: j, err: discordgo.ErrVoiceNotReady})
	if j.snapshot.LastSubmittedSequence != 0 || j.frames.count != 1 || g.inflight != nil || g.closing {
		t.Fatal("readiness race lost/replayed/failed unsubmitted input")
	}
}
func TestReceiptFailureNeverRewindsOrReplays(t *testing.T) {
	g, f, p := fixtureGuild(t)
	j := fixtureJob(t, g, p, "job", 1)
	acceptFixture(t, g, j, 1)
	acceptFixture(t, g, j, 2)
	sent := handoffFixture(t, g, f, j)
	receiptFixture(t, g, sent, errors.New("opaque internal transport failure"))
	if j.snapshot.LastSubmittedSequence != 1 || j.snapshot.LastUdpWrittenSequence != 0 || !g.closing || !g.forceClose {
		t.Fatal("ambiguous submitted frame was rewound")
	}
	if g.service.usage.frames == 0 || f.leaves.Load() != 0 {
		t.Fatal("packet ownership or channel reservation released before local cleanup")
	}
	if err := <-g.aborted; err != nil {
		t.Fatal(err)
	}
	g.aborting = false
	g.finishAbort()
	if j.snapshot.State != wire.PlaybackState_PLAYBACK_STATE_FAILED || !j.snapshot.TerminalError.MayHaveSubmitted {
		t.Fatal("UDP failure presented as completion")
	}
	g.schedule()
	if err := <-g.closed; err != nil {
		t.Fatal(err)
	}
	if f.leaves.Load() != 1 {
		t.Fatal("last-reference disconnect did not occur exactly once")
	}
	select {
	case <-f.sent:
		t.Fatal("failed frame replayed")
	default:
	}
}
