package voicejobs

import (
	"context"
	"math"
	"time"

	"github.com/bwmarrin/discordgo"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func readyEvent(v *wire.VoiceSubscriptionSnapshot) *wire.VoiceReceiveEvent {
	return &wire.VoiceReceiveEvent{Event: &wire.VoiceReceiveEvent_Ready{Ready: proto.Clone(v).(*wire.VoiceSubscriptionSnapshot)}}
}
func (h *server) SubscribeVoice(r *wire.SubscribeVoiceRequest, stream grpc.ServerStreamingServer[wire.VoiceReceiveEvent]) error {
	ctx := stream.Context()
	p, done, err := h.begin(ctx, "SubscribeVoice")
	if err != nil {
		return err
	}
	defer done()
	s := h.service
	life, err := s.instanceLifetime(p)
	if err != nil {
		return err
	}
	if r == nil || proto.Size(r) > s.config.MaxGRPCMessageBytes || !validLifetime(r.Lifetime, s.config.SubscriptionLifetime) {
		return admissionInvalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_LIFETIME)
	}
	if len(r.Ssrcs) > s.config.MaxSSRCFilters {
		return admissionInvalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_FILTER)
	}
	filters := map[uint32]struct{}{}
	for _, ssrc := range r.Ssrcs {
		if _, ok := filters[ssrc]; ok {
			return admissionInvalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_FILTER)
		}
		filters[ssrc] = struct{}{}
	}
	if err = h.target(ctx, p, "SubscribeVoice", r.GuildId, r.ChannelId, nil); err != nil {
		return err
	}
	id, err := opaque()
	if err != nil {
		return err
	}
	g, err := s.actor(r.GuildId, r.ChannelId)
	if err != nil {
		return err
	}
	value, err := g.ask(ctx, func(g *guild) (any, error) {
		if g.closing {
			return nil, failure(codes.FailedPrecondition, wire.VoiceErrorReason_VOICE_ERROR_REASON_CHANNEL_CONFLICT, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_ADMISSION)
		}
		s.mu.Lock()
		i := s.instances[p.InstanceID]
		if i == nil || !i.active || i.draining || i.ctx.Err() != nil {
			s.mu.Unlock()
			return nil, failure(codes.FailedPrecondition, wire.VoiceErrorReason_VOICE_ERROR_REASON_DRAINING, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_ADMISSION)
		}
		if s.subs[id] != nil {
			s.mu.Unlock()
			return nil, failure(codes.Internal, wire.VoiceErrorReason_VOICE_ERROR_REASON_INTERNAL, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_ADMISSION)
		}
		if i.usage.subs >= s.config.InstanceSubscriptions || s.usage.subs >= s.config.HostSubscriptions || len(g.subs) >= s.config.GuildSubscriptions || g.owners[p.InstanceID] == 0 && i.usage.sessions >= s.config.InstanceSessions {
			s.mu.Unlock()
			return nil, quota()
		}
		i.usage.subs++
		s.usage.subs++
		if g.owners[p.InstanceID] == 0 {
			i.usage.sessions++
		}
		g.owners[p.InstanceID]++
		s.subs[id] = &subRef{owner: p, guild: g.id, channel: g.channel, actor: g}
		s.mu.Unlock()
		v := &subscription{id: id, owner: p, snapshot: &wire.VoiceSubscriptionSnapshot{SubscriptionId: id, GuildId: g.id, ChannelId: g.channel, State: wire.VoiceSubscriptionState_VOICE_SUBSCRIPTION_STATE_JOINING, ExpiresAt: timestamppb.New(time.Now().Add(r.Lifetime.AsDuration()))}, filters: filters, events: make(chan *wire.VoiceReceiveEvent, s.config.SubscriptionPackets+2), released: make(chan struct{}), pendingSince: time.Now()}
		v.header = readyEvent(v.snapshot)
		g.subs[id] = v
		g.initialized = true
		if g.transport != nil && g.transport.ReadyState() {
			v.snapshot.State = wire.VoiceSubscriptionState_VOICE_SUBSCRIPTION_STATE_ACTIVE
			g.subEvent(v, readyEvent(v.snapshot))
		}
		return v, nil
	})
	g.releaseAdmission()
	if err != nil {
		return err
	}
	v := value.(*subscription)
	cause := failure(codes.Canceled, wire.VoiceErrorReason_VOICE_ERROR_REASON_STREAM_CANCELLED, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_RECEIVE)
	defer func() {
		if life.Err() != nil {
			cause = stopped()
		}
		g.post(func(g *guild) (any, error) {
			if !v.terminal {
				g.finishSub(v, cause)
			}
			g.releaseSub(v)
			return nil, nil
		})
	}()
	stop := make(chan struct{})
	defer close(stop)
	outcome := make(chan error, 1)
	go func() {
		event := v.header
		for {
			if event == nil {
				select {
				case event = <-v.events:
				case <-stop:
					return
				case <-ctx.Done():
					return
				}
			}
			alarm := time.AfterFunc(s.config.SlowConsumerTimeout, func() {
				select {
				case outcome <- timeout(wire.VoiceErrorReason_VOICE_ERROR_REASON_RECEIVE_TIMEOUT, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_RECEIVE):
				default:
				}
			})
			e := stream.Send(event)
			fired := !alarm.Stop()
			if fired {
				return
			}
			if e != nil {
				select {
				case outcome <- e:
				default:
				}
				return
			}
			delivered := event
			g.post(func(g *guild) (any, error) { g.ackSub(v, delivered); return nil, nil })
			if event.GetTerminal() != nil {
				select {
				case outcome <- nil:
				default:
				}
				return
			}
			event = nil
		}
	}()
	select {
	case err := <-outcome:
		if err != nil {
			cause = streamFailure(err)
			cause.detail.Stage = wire.VoiceFailureStage_VOICE_FAILURE_STAGE_RECEIVE
		}
		return err
	case <-ctx.Done():
		cause = streamFailure(ctx.Err())
		cause.detail.Stage = wire.VoiceFailureStage_VOICE_FAILURE_STAGE_RECEIVE
		return ctx.Err()
	case <-life.Done():
		return stopped()
	case <-v.released:
		return timeout(wire.VoiceErrorReason_VOICE_ERROR_REASON_RECEIVE_TIMEOUT, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_RECEIVE)
	}
}
func (g *guild) subEvent(v *subscription, event *wire.VoiceReceiveEvent) {
	if v.pendingSince.IsZero() {
		v.pendingSince = time.Now()
	}
	select {
	case v.events <- event:
	default:
		g.finishSub(v, failure(codes.ResourceExhausted, wire.VoiceErrorReason_VOICE_ERROR_REASON_RECEIVE_OVERFLOW, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_RECEIVE))
	}
}
func (g *guild) fanout(p *discordgo.Packet) {
	if g.closing || p == nil {
		return
	}
	if len(p.Opus) > g.service.config.MaxOpusPacketBytes || g.receiveSequence == math.MaxUint64 {
		g.failAll(failure(codes.Internal, wire.VoiceErrorReason_VOICE_ERROR_REASON_INTERNAL, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_RECEIVE))
		return
	}
	g.receiveSequence++
	now := time.Now()
	for _, v := range g.subs {
		if v.terminal || !v.deliveryActive || v.snapshot.State != wire.VoiceSubscriptionState_VOICE_SUBSCRIPTION_STATE_ACTIVE {
			continue
		}
		if len(v.filters) > 0 {
			if _, ok := v.filters[p.SSRC]; !ok {
				continue
			}
		}
		n := int64(len(p.Opus))
		s := g.service
		s.mu.Lock()
		fits := v.packets < s.config.SubscriptionPackets && v.bytes <= s.config.SubscriptionBytes-n && s.receivePackets < s.config.HostReceivePackets && s.receiveBytes <= s.config.HostReceiveBytes-n
		if fits {
			v.packets++
			v.bytes += n
			s.receivePackets++
			s.receiveBytes += n
		}
		s.mu.Unlock()
		if !fits {
			g.finishSub(v, failure(codes.ResourceExhausted, wire.VoiceErrorReason_VOICE_ERROR_REASON_RECEIVE_OVERFLOW, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_RECEIVE))
			continue
		}
		packet := &wire.VoicePacket{SubscriptionId: v.id, Ssrc: p.SSRC, RtpSequence: uint32(p.Sequence), RtpTimestamp: p.Timestamp, ReceiveSequence: g.receiveSequence, ReceivedAt: timestamppb.New(now), Opus: p.Opus}
		event := &wire.VoiceReceiveEvent{Event: &wire.VoiceReceiveEvent_Packet{Packet: packet}}
		if proto.Size(event) > s.config.MaxGRPCMessageBytes {
			g.releasePacket(v, n)
			g.finishSub(v, failure(codes.ResourceExhausted, wire.VoiceErrorReason_VOICE_ERROR_REASON_RECEIVE_OVERFLOW, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_RECEIVE))
			continue
		}
		g.subEvent(v, event)
	}
}
func (g *guild) ackSub(v *subscription, event *wire.VoiceReceiveEvent) {
	if _, ok := g.subs[v.id]; !ok {
		return
	}
	if p := event.GetPacket(); p != nil {
		g.releasePacket(v, int64(len(p.Opus)))
	}
	if ready := event.GetReady(); ready != nil && ready.State == wire.VoiceSubscriptionState_VOICE_SUBSCRIPTION_STATE_ACTIVE && !v.terminal {
		v.deliveryActive = true
	}
	if len(v.events) == 0 {
		v.pendingSince = time.Time{}
	} else {
		v.pendingSince = time.Now()
	}
}
func (g *guild) releasePacket(v *subscription, n int64) {
	s := g.service
	s.mu.Lock()
	v.packets--
	v.bytes -= n
	s.receivePackets--
	s.receiveBytes -= n
	s.signalLocked()
	s.mu.Unlock()
}
func (g *guild) finishSub(v *subscription, e *voiceFailure) {
	if v.terminal {
		return
	}
	v.terminal = true
	v.snapshot.State = wire.VoiceSubscriptionState_VOICE_SUBSCRIPTION_STATE_CLOSED
	if e != nil {
		v.snapshot.State = wire.VoiceSubscriptionState_VOICE_SUBSCRIPTION_STATE_FAILED
		if codes.Code(e.detail.GrpcCode) == codes.Canceled {
			v.snapshot.State = wire.VoiceSubscriptionState_VOICE_SUBSCRIPTION_STATE_CLOSED
		}
		d := proto.Clone(e.detail).(*wire.VoiceError)
		d.GuildId = g.id
		d.ChannelId = g.channel
		d.SubscriptionId = v.id
		v.snapshot.TerminalError = d
	}
	for {
		select {
		case event := <-v.events:
			if p := event.GetPacket(); p != nil {
				g.releasePacket(v, int64(len(p.Opus)))
			}
		default:
			goto drained
		}
	}
drained:
	v.events <- &wire.VoiceReceiveEvent{Event: &wire.VoiceReceiveEvent_Terminal{Terminal: proto.Clone(v.snapshot).(*wire.VoiceSubscriptionSnapshot)}}
	v.pendingSince = time.Now()
	s := g.service
	s.mu.Lock()
	if ref := s.subs[v.id]; ref != nil {
		ref.final = proto.Clone(v.snapshot).(*wire.VoiceSubscriptionSnapshot)
		ref.at = time.Now()
	}
	s.pruneLocked(time.Now())
	s.notifyRecordsLocked()
	s.signalLocked()
	s.mu.Unlock()
}
func (g *guild) releaseSub(v *subscription) {
	if _, ok := g.subs[v.id]; !ok {
		return
	}
	for {
		select {
		case event := <-v.events:
			if p := event.GetPacket(); p != nil {
				g.releasePacket(v, int64(len(p.Opus)))
			}
		default:
			goto drained
		}
	}
drained:
	// A canceled gRPC send can still hold one immutable packet. Account its
	// remaining envelope until handler release; the writer never mutates it.
	if v.packets > 0 {
		n := v.bytes
		s := g.service
		s.mu.Lock()
		s.receivePackets -= v.packets
		s.receiveBytes -= n
		v.packets = 0
		v.bytes = 0
		s.mu.Unlock()
	}
	delete(g.subs, v.id)
	close(v.released)
	g.releaseOwner(v.owner, false)
	g.service.mu.Lock()
	if ref := g.service.subs[v.id]; ref != nil {
		ref.actor = nil
	}
	g.service.mu.Unlock()
	// The terminal snapshot is immutable: canceled RPC reply slots share it
	// rather than allocating an unaccounted full snapshot for each waiter.
	for _, waiter := range v.waiters {
		waiter <- answer{value: v.snapshot}
	}
	v.waiters = nil
}
func (h *server) UnsubscribeVoice(ctx context.Context, r *wire.UnsubscribeVoiceRequest) (*wire.VoiceSubscriptionSnapshot, error) {
	p, done, err := h.begin(ctx, "UnsubscribeVoice")
	if err != nil {
		return nil, err
	}
	defer done()
	if r == nil {
		return nil, notFound()
	}
	s := h.service
	s.mu.Lock()
	s.pruneLocked(time.Now())
	ref := s.subs[r.SubscriptionId]
	var copy *subRef
	if ref != nil && ref.owner == p {
		value := *ref
		copy = &value
	}
	s.mu.Unlock()
	if copy == nil {
		return nil, notFound()
	}
	if err = h.authorize(ctx, "UnsubscribeVoice", copy.guild, copy.channel, nil); err != nil {
		return nil, err
	}
	if copy.final != nil && copy.actor == nil {
		return proto.Clone(copy.final).(*wire.VoiceSubscriptionSnapshot), nil
	}
	reply := make(chan answer, 1)
	value, err := copy.actor.execute(ctx, command{ctx: ctx, reply: reply, run: func(g *guild) (any, error) {
		v := g.subs[r.SubscriptionId]
		if v == nil {
			return nil, notFound()
		}
		if len(v.waiters) >= s.config.ControlMailbox {
			return nil, quota()
		}
		v.waiters = append(v.waiters, reply)
		g.finishSub(v, nil)
		return nil, errDeferred
	}})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if final := s.retainedSub(p, r.SubscriptionId); final != nil {
			return final, nil
		}
		return nil, err
	}
	return value.(*wire.VoiceSubscriptionSnapshot), nil
}
