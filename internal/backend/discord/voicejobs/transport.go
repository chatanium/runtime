package voicejobs

import (
	"context"
	"errors"
	"time"

	"github.com/bwmarrin/discordgo"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Transport is host-private. Implementations must keep submitted bytes immutable
// until their receipt and must never replay a failed or ambiguous handoff.
type Transport interface {
	SubmitOpus(context.Context, []byte) (Submission, error)
	ReceiveOpus(context.Context) (*discordgo.Packet, error)
	// ReceiveOpus transfers an owned immutable packet, never borrowed scratch.
	ReadyState() bool
	ReadinessChanged() <-chan struct{}
	Done() <-chan struct{}
	Err() error
	SetStateContext(context.Context, bool, bool) error
	CloseContext(context.Context) error
	DisconnectContext(context.Context) error
}
type Factory func(context.Context, string, string, bool, bool) (Transport, error)
type Submission interface {
	Done() <-chan discordgo.OpusWriteResult
}
type sdkTransport struct{ *discordgo.VoiceConnection }

func (v sdkTransport) SubmitOpus(ctx context.Context, p []byte) (Submission, error) {
	return v.VoiceConnection.SubmitOpus(ctx, p)
}

func sdkFactory(s *discordgo.Session, c discordgo.VoiceConfig) Factory {
	return func(ctx context.Context, guild, channel string, mute, deaf bool) (Transport, error) {
		v, err := s.ChannelVoiceJoinContext(ctx, guild, channel, mute, deaf, c)
		if err != nil {
			return nil, err
		}
		return sdkTransport{v}, nil
	}
}

type voiceFailure struct{ detail *wire.VoiceError }

func (e *voiceFailure) Error() string { return e.detail.Reason.String() }
func (e *voiceFailure) GRPCStatus() *status.Status {
	s := status.New(codes.Code(e.detail.GrpcCode), e.detail.Reason.String())
	d, err := s.WithDetails(e.detail)
	if err == nil {
		return d
	}
	return s
}
func failure(code codes.Code, reason wire.VoiceErrorReason, stage wire.VoiceFailureStage) *voiceFailure {
	return &voiceFailure{detail: &wire.VoiceError{GrpcCode: int32(code), Reason: reason, Stage: stage, Message: reason.String()}}
}
func invalid(reason wire.VoiceErrorReason) error {
	return failure(codes.InvalidArgument, reason, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_INPUT)
}
func quota() error {
	return failure(codes.ResourceExhausted, wire.VoiceErrorReason_VOICE_ERROR_REASON_QUOTA_EXCEEDED, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_ADMISSION)
}
func notFound() error {
	return failure(codes.NotFound, wire.VoiceErrorReason_VOICE_ERROR_REASON_NOT_FOUND, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONTROL)
}
func timeout(reason wire.VoiceErrorReason, stage wire.VoiceFailureStage) *voiceFailure {
	return failure(codes.DeadlineExceeded, reason, stage)
}
func stopped() *voiceFailure {
	return failure(codes.Canceled, wire.VoiceErrorReason_VOICE_ERROR_REASON_INSTANCE_STOPPED, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CLEANUP)
}
func terminal(s wire.PlaybackState) bool {
	return s == wire.PlaybackState_PLAYBACK_STATE_COMPLETED || s == wire.PlaybackState_PLAYBACK_STATE_CANCELLED || s == wire.PlaybackState_PLAYBACK_STATE_FAILED
}
func earlier(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}
func transportFailure(err error, stage wire.VoiceFailureStage) *voiceFailure {
	if v, ok := err.(*voiceFailure); ok {
		return v
	}
	switch {
	case errors.Is(err, discordgo.ErrVoicePermissionDenied):
		return failure(codes.PermissionDenied, wire.VoiceErrorReason_VOICE_ERROR_REASON_DISCORD_PERMISSION_DENIED, stage)
	case errors.Is(err, discordgo.ErrVoiceChannelChanged):
		return failure(codes.Unavailable, wire.VoiceErrorReason_VOICE_ERROR_REASON_CHANNEL_CHANGED, stage)
	case errors.Is(err, discordgo.ErrVoiceUnavailable):
		return failure(codes.Unavailable, wire.VoiceErrorReason_VOICE_ERROR_REASON_VOICE_TRANSPORT_UNSUPPORTED, stage)
	case errors.Is(err, discordgo.ErrVoiceDAVETimeout):
		return timeout(wire.VoiceErrorReason_VOICE_ERROR_REASON_DAVE_NOT_READY, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_DAVE)
	case errors.Is(err, context.DeadlineExceeded):
		reason := wire.VoiceErrorReason_VOICE_ERROR_REASON_CONNECTION_TIMEOUT
		switch stage {
		case wire.VoiceFailureStage_VOICE_FAILURE_STAGE_SUBMISSION:
			reason = wire.VoiceErrorReason_VOICE_ERROR_REASON_SUBMISSION_TIMEOUT
		case wire.VoiceFailureStage_VOICE_FAILURE_STAGE_UDP_WRITE:
			reason = wire.VoiceErrorReason_VOICE_ERROR_REASON_RECEIPT_TIMEOUT
		case wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CLEANUP:
			reason = wire.VoiceErrorReason_VOICE_ERROR_REASON_CLEANUP_TIMEOUT
		}
		return timeout(reason, stage)
	}
	return failure(codes.Unavailable, wire.VoiceErrorReason_VOICE_ERROR_REASON_CONNECTION_LOST, stage)
}
func streamFailure(err error) *voiceFailure {
	if v, ok := err.(*voiceFailure); ok {
		return v
	}
	code := codes.Unavailable
	if errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled {
		code = codes.Canceled
	} else if errors.Is(err, context.DeadlineExceeded) || status.Code(err) == codes.DeadlineExceeded {
		code = codes.DeadlineExceeded
	}
	return failure(code, wire.VoiceErrorReason_VOICE_ERROR_REASON_STREAM_CANCELLED, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_INPUT)
}
func admissionInvalid(reason wire.VoiceErrorReason) error {
	return failure(codes.InvalidArgument, reason, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_ADMISSION)
}
