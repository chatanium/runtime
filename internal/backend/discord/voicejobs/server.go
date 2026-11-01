package voicejobs

import (
	"context"
	"time"

	rt "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
)

type server struct {
	wire.UnimplementedVoiceServiceServer
	service  *Service
	services rt.InstanceServices
}

func (h *server) begin(ctx context.Context, operation string) (rt.InstancePrincipal, func(), error) {
	if _, err := rt.PrincipalFromContext(ctx); err != nil {
		return rt.InstancePrincipal{}, nil, err
	}
	p, err := h.services.Authorizer.AwaitOperation(ctx, "discord", operation)
	if err != nil {
		return p, nil, err
	}
	if p != h.services.Principal {
		return p, nil, notFound()
	}
	s := h.service
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.instances[p.InstanceID]
	if i == nil || i.services.Principal != p || i.ctx.Err() != nil {
		return p, nil, stopped()
	}
	n := int64(s.config.MaxGRPCMessageBytes) * 2
	if i.usage.messages > s.config.InstanceMessageBytes-n || s.usage.messages > s.config.HostMessageBytes-n {
		return p, nil, quota()
	}
	i.usage.messages += n
	s.usage.messages += n
	return p, func() { s.mu.Lock(); i.usage.messages -= n; s.usage.messages -= n; s.signalLocked(); s.mu.Unlock() }, nil
}
func (h *server) authorize(ctx context.Context, op, guild, channel string, priority *int32) error {
	ids := map[string]string{"guild_id": guild}
	if channel != "" {
		ids["channel_id"] = channel
	}
	_, err := h.services.Authorizer.Authorize(ctx, rt.AccessRequest{Backend: "discord", Operation: op, Scopes: []*corewire.ResourceScope{{SelectorKind: &corewire.ResourceScope_Selector{Selector: &corewire.ResourceSelector{ResourceIds: ids}}}}})
	if err != nil {
		return err
	}
	if priority != nil {
		a, e := rt.AdmissionFromContext(ctx)
		if e != nil {
			return e
		}
		grant, e := a.CapabilityGrant()
		if e != nil {
			return e
		}
		c := new(wire.VoicePlaybackConstraints)
		if grant.Constraints == nil || grant.Constraints.UnmarshalTo(c) != nil || *priority > c.MaxPriority {
			return failure(codes.PermissionDenied, wire.VoiceErrorReason_VOICE_ERROR_REASON_PERMISSION_DENIED, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_ADMISSION)
		}
	}
	return nil
}
func (h *server) target(ctx context.Context, p rt.InstancePrincipal, op, guild, channel string, priority *int32) error {
	if !snowflake(guild) || !snowflake(channel) {
		return invalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE)
	}
	lookup, cancel := context.WithTimeout(ctx, h.service.config.RelationshipTimeout)
	defer cancel()
	actual, err := h.service.resolve(lookup, p, channel)
	if err != nil {
		return err
	}
	if actual != guild {
		return failure(codes.PermissionDenied, wire.VoiceErrorReason_VOICE_ERROR_REASON_PERMISSION_DENIED, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_ADMISSION)
	}
	return h.authorize(ctx, op, guild, channel, priority)
}
func snowflake(v string) bool {
	if len(v) == 0 || len(v) > 20 {
		return false
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return false
		}
	}
	return v != "0"
}
func (h *server) CreatePlaybackJob(ctx context.Context, r *wire.CreatePlaybackJobRequest) (*wire.PlaybackSnapshot, error) {
	p, done, err := h.begin(ctx, "CreatePlaybackJob")
	if err != nil {
		return nil, err
	}
	defer done()
	if r == nil || proto.Size(r) > h.service.config.MaxGRPCMessageBytes {
		return nil, admissionInvalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE)
	}
	if !validLifetime(r.Lifetime, h.service.config.JobLifetime) {
		return nil, admissionInvalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_LIFETIME)
	}
	if r.Format != wire.OpusFormat_OPUS_FORMAT_OPUS_48KHZ_20MS {
		return nil, admissionInvalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_UNSUPPORTED_FORMAT)
	}
	if err = h.target(ctx, p, "CreatePlaybackJob", r.GuildId, r.ChannelId, &r.Priority); err != nil {
		return nil, err
	}
	id, err := opaque()
	if err != nil {
		return nil, err
	}
	g, err := h.service.actor(r.GuildId, r.ChannelId)
	if err != nil {
		return nil, err
	}
	value, err := g.ask(ctx, func(g *guild) (any, error) { return g.createJob(p, id, r) })
	g.releaseAdmission()
	if err != nil {
		return nil, err
	}
	return value.(*wire.PlaybackSnapshot), nil
}
func (h *server) job(ctx context.Context, p rt.InstancePrincipal, id, op string) (*jobRef, error) {
	s := h.service
	s.mu.Lock()
	s.pruneLocked(time.Now())
	r := s.jobs[id]
	var out *jobRef
	if r != nil && r.owner == p {
		copy := *r
		out = &copy
	}
	s.mu.Unlock()
	if out == nil {
		return nil, notFound()
	}
	if err := h.authorize(ctx, op, out.guild, out.channel, nil); err != nil {
		return nil, err
	}
	return out, nil
}
func (h *server) control(ctx context.Context, r *wire.JobRequest, op string) (*wire.PlaybackSnapshot, error) {
	p, done, err := h.begin(ctx, op)
	if err != nil {
		return nil, err
	}
	defer done()
	if r == nil {
		return nil, notFound()
	}
	ref, err := h.job(ctx, p, r.JobId, op)
	if err != nil {
		return nil, err
	}
	if ref.final != nil {
		if op == "CancelPlaybackJob" {
			return proto.Clone(ref.final).(*wire.PlaybackSnapshot), nil
		}
		return nil, failure(codes.FailedPrecondition, wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONTROL)
	}
	reply := make(chan answer, 1)
	c := command{ctx: ctx, reply: reply, run: func(g *guild) (any, error) { return g.controlJob(r.JobId, op, reply) }}
	value, err := ref.actor.execute(ctx, c)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if final := h.service.retainedJob(p, r.JobId); final != nil {
			if op == "CancelPlaybackJob" {
				return final, nil
			}
			return nil, failure(codes.FailedPrecondition, wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONTROL)
		}
		return nil, err
	}
	return value.(*wire.PlaybackSnapshot), nil
}
func (h *server) PausePlaybackJob(ctx context.Context, r *wire.JobRequest) (*wire.PlaybackSnapshot, error) {
	return h.control(ctx, r, "PausePlaybackJob")
}
func (h *server) ResumePlaybackJob(ctx context.Context, r *wire.JobRequest) (*wire.PlaybackSnapshot, error) {
	return h.control(ctx, r, "ResumePlaybackJob")
}
func (h *server) CancelPlaybackJob(ctx context.Context, r *wire.JobRequest) (*wire.PlaybackSnapshot, error) {
	return h.control(ctx, r, "CancelPlaybackJob")
}
