package discordv2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type JobID string
type SubscriptionID string
type OpusFormat = wire.OpusFormat
type PlaybackState = wire.PlaybackState
type PlaybackReason = wire.PlaybackReason
type SubscriptionState = wire.VoiceSubscriptionState
type VoiceErrorReason = wire.VoiceErrorReason
type VoiceFailureStage = wire.VoiceFailureStage

const (
	Opus48kHz20ms                OpusFormat        = wire.OpusFormat_OPUS_FORMAT_OPUS_48KHZ_20MS
	PlaybackQueued               PlaybackState     = wire.PlaybackState_PLAYBACK_STATE_QUEUED
	PlaybackRunning              PlaybackState     = wire.PlaybackState_PLAYBACK_STATE_RUNNING
	PlaybackPaused               PlaybackState     = wire.PlaybackState_PLAYBACK_STATE_PAUSED
	PlaybackCompleted            PlaybackState     = wire.PlaybackState_PLAYBACK_STATE_COMPLETED
	PlaybackCancelled            PlaybackState     = wire.PlaybackState_PLAYBACK_STATE_CANCELLED
	PlaybackFailed               PlaybackState     = wire.PlaybackState_PLAYBACK_STATE_FAILED
	SubscriptionJoining          SubscriptionState = wire.VoiceSubscriptionState_VOICE_SUBSCRIPTION_STATE_JOINING
	SubscriptionActive           SubscriptionState = wire.VoiceSubscriptionState_VOICE_SUBSCRIPTION_STATE_ACTIVE
	SubscriptionClosed           SubscriptionState = wire.VoiceSubscriptionState_VOICE_SUBSCRIPTION_STATE_CLOSED
	SubscriptionFailed           SubscriptionState = wire.VoiceSubscriptionState_VOICE_SUBSCRIPTION_STATE_FAILED
	PlaybackWaitingConnection    PlaybackReason    = wire.PlaybackReason_PLAYBACK_REASON_WAITING_CONNECTION
	PlaybackWaitingInput         PlaybackReason    = wire.PlaybackReason_PLAYBACK_REASON_WAITING_INPUT
	PlaybackWaitingPriority      PlaybackReason    = wire.PlaybackReason_PLAYBACK_REASON_WAITING_PRIORITY
	PlaybackPreempted            PlaybackReason    = wire.PlaybackReason_PLAYBACK_REASON_PREEMPTED
	PlaybackPlaying              PlaybackReason    = wire.PlaybackReason_PLAYBACK_REASON_PLAYING
	PlaybackOwnerPaused          PlaybackReason    = wire.PlaybackReason_PLAYBACK_REASON_OWNER_PAUSED
	PlaybackInputDrained         PlaybackReason    = wire.PlaybackReason_PLAYBACK_REASON_INPUT_DRAINED
	PlaybackOwnerCancelled       PlaybackReason    = wire.PlaybackReason_PLAYBACK_REASON_OWNER_CANCELLED
	PlaybackStreamCancelled      PlaybackReason    = wire.PlaybackReason_PLAYBACK_REASON_STREAM_CANCELLED
	PlaybackInstanceStopped      PlaybackReason    = wire.PlaybackReason_PLAYBACK_REASON_INSTANCE_STOPPED
	PlaybackError                PlaybackReason    = wire.PlaybackReason_PLAYBACK_REASON_ERROR
	PlaybackWaitingDAVE          PlaybackReason    = wire.PlaybackReason_PLAYBACK_REASON_WAITING_DAVE
	VoiceChannelConflict         VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_CHANNEL_CONFLICT
	VoiceInputTruncated          VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_INPUT_TRUNCATED
	VoiceInvalidOpus             VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_OPUS
	VoiceUnsupportedFormat       VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_UNSUPPORTED_FORMAT
	VoiceInvalidSequence         VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_SEQUENCE
	VoiceInvalidFinalSequence    VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_FINAL_SEQUENCE
	VoiceCreditExceeded          VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_CREDIT_EXCEEDED
	VoiceInvalidLifetime         VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_LIFETIME
	VoiceInvalidFilter           VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_FILTER
	VoiceInvalidState            VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE
	VoiceProducerAlreadyBound    VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_PRODUCER_ALREADY_BOUND
	VoiceInputAfterEnd           VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_INPUT_AFTER_END
	VoiceDraining                VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_DRAINING
	VoiceQuotaExceeded           VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_QUOTA_EXCEEDED
	VoiceReceiveOverflow         VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_RECEIVE_OVERFLOW
	VoiceLifetimeExceeded        VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_LIFETIME_EXCEEDED
	VoiceBindTimeout             VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_BIND_TIMEOUT
	VoiceInputTimeout            VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_INPUT_TIMEOUT
	VoiceConnectionTimeout       VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_CONNECTION_TIMEOUT
	VoiceReceiveTimeout          VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_RECEIVE_TIMEOUT
	VoiceSubmissionTimeout       VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_SUBMISSION_TIMEOUT
	VoiceReceiptTimeout          VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_RECEIPT_TIMEOUT
	VoiceCleanupTimeout          VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_CLEANUP_TIMEOUT
	VoiceOwnerCancelled          VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_OWNER_CANCELLED
	VoiceStreamCancelled         VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_STREAM_CANCELLED
	VoiceInstanceStopped         VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_INSTANCE_STOPPED
	VoiceConnectionLost          VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_CONNECTION_LOST
	VoiceChannelChanged          VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_CHANNEL_CHANGED
	VoiceTransportFailure        VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_TRANSPORT_FAILURE
	VoiceTransportUnsupported    VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_VOICE_TRANSPORT_UNSUPPORTED
	VoiceDAVENotReady            VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_DAVE_NOT_READY
	VoiceInternal                VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_INTERNAL
	VoiceUnauthenticated         VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_UNAUTHENTICATED
	VoicePermissionDenied        VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_PERMISSION_DENIED
	VoiceNotFound                VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_NOT_FOUND
	VoiceSequenceExhausted       VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_SEQUENCE_EXHAUSTED
	VoiceStaleContinuation       VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_STALE_CONTINUATION
	VoiceDiscordPermissionDenied VoiceErrorReason  = wire.VoiceErrorReason_VOICE_ERROR_REASON_DISCORD_PERMISSION_DENIED
	VoiceStageAdmission          VoiceFailureStage = wire.VoiceFailureStage_VOICE_FAILURE_STAGE_ADMISSION
	VoiceStageConnection         VoiceFailureStage = wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONNECTION
	VoiceStageDAVE               VoiceFailureStage = wire.VoiceFailureStage_VOICE_FAILURE_STAGE_DAVE
	VoiceStageBind               VoiceFailureStage = wire.VoiceFailureStage_VOICE_FAILURE_STAGE_BIND
	VoiceStageInput              VoiceFailureStage = wire.VoiceFailureStage_VOICE_FAILURE_STAGE_INPUT
	VoiceStageSubmission         VoiceFailureStage = wire.VoiceFailureStage_VOICE_FAILURE_STAGE_SUBMISSION
	VoiceStageUDPWrite           VoiceFailureStage = wire.VoiceFailureStage_VOICE_FAILURE_STAGE_UDP_WRITE
	VoiceStageReceive            VoiceFailureStage = wire.VoiceFailureStage_VOICE_FAILURE_STAGE_RECEIVE
	VoiceStageControl            VoiceFailureStage = wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONTROL
	VoiceStageCleanup            VoiceFailureStage = wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CLEANUP
)

type CreatePlaybackJobRequest struct {
	GuildID, ChannelID string
	Priority           int32
	Lifetime           time.Duration
	Format             OpusFormat
}
type JobRequest struct{ JobID JobID }
type PlaybackSnapshot struct {
	JobID                                                               JobID
	GuildID, ChannelID                                                  string
	Priority                                                            int32
	State                                                               PlaybackState
	Reason                                                              PlaybackReason
	LastAcceptedSequence, LastSubmittedSequence, LastUDPWrittenSequence uint64
	InputEnded                                                          bool
	FinalSequence                                                       uint64
	CreditThroughSequence, CreditThroughBytes                           uint64
	ExpiresAt                                                           time.Time
	TerminalError                                                       *VoiceError
}

func (s PlaybackSnapshot) Terminal() bool {
	return s.State == PlaybackCompleted || s.State == PlaybackCancelled || s.State == PlaybackFailed
}

type PlaybackInput struct {
	Bind     *JobRequest
	Frame    *OpusFrame
	EndInput *PlaybackEnd
}
type OpusFrame struct {
	Sequence uint64
	Opus     []byte
}
type PlaybackEnd struct{ FinalSequence uint64 }
type PlaybackQueueRequest struct {
	GuildID      string
	Limit        uint32
	Continuation string
}
type PlaybackQueue struct {
	Jobs             []PlaybackSnapshot
	NextContinuation string
}
type SubscribeVoiceRequest struct {
	GuildID, ChannelID string
	Lifetime           time.Duration
	SSRCs              []uint32
}
type VoicePacket struct {
	SubscriptionID                  SubscriptionID
	SSRC, RTPSequence, RTPTimestamp uint32
	ReceiveSequence                 uint64
	ReceivedAt                      time.Time
	// Opus belongs to this event. The client never reuses its backing storage.
	Opus []byte
}
type VoiceReceiveEvent struct {
	Ready    *VoiceSubscriptionSnapshot
	Packet   *VoicePacket
	Terminal *VoiceSubscriptionSnapshot
}
type VoiceSubscriptionSnapshot struct {
	SubscriptionID     SubscriptionID
	GuildID, ChannelID string
	State              SubscriptionState
	ExpiresAt          time.Time
	TerminalError      *VoiceError
}
type UnsubscribeVoiceRequest struct{ SubscriptionID SubscriptionID }

// VoiceError preserves the safe, typed voice failure detail and gRPC status.
// A UDP-written cursor proves only a local socket write, never audible delivery.
type VoiceError struct {
	Code                        codes.Code
	Reason                      VoiceErrorReason
	Stage                       VoiceFailureStage
	Message, GuildID, ChannelID string
	JobID                       JobID
	SubscriptionID              SubscriptionID
	MayHaveSubmitted            bool
}

func (e *VoiceError) Error() string { return fmt.Sprintf("voice %s: %s", e.Code, e.Message) }
func (e *VoiceError) GRPCStatus() *status.Status {
	s := status.New(e.Code, e.Message)
	with, err := s.WithDetails(&wire.VoiceError{GrpcCode: int32(e.Code), Reason: e.Reason, Stage: e.Stage, Message: e.Message, GuildId: e.GuildID, ChannelId: e.ChannelID, JobId: string(e.JobID), SubscriptionId: string(e.SubscriptionID), MayHaveSubmitted: e.MayHaveSubmitted})
	if err == nil {
		return with
	}
	return s
}
func voiceError(v *wire.VoiceError) *VoiceError {
	if v == nil {
		return nil
	}
	return &VoiceError{Code: codes.Code(v.GrpcCode), Reason: v.Reason, Stage: v.Stage, Message: v.Message, GuildID: v.GuildId, ChannelID: v.ChannelId, JobID: JobID(v.JobId), SubscriptionID: SubscriptionID(v.SubscriptionId), MayHaveSubmitted: v.MayHaveSubmitted}
}
func voiceRPCError(err error) error {
	if err == nil {
		return nil
	}
	for _, detail := range status.Convert(err).Details() {
		if v, ok := detail.(*wire.VoiceError); ok {
			return voiceError(v)
		}
	}
	return err
}
func voiceProtocol(message string) error {
	return status.Error(codes.Internal, "invalid voice response: "+message)
}
func voiceInvalid(message string) error { return status.Error(codes.InvalidArgument, message) }
func voiceState(message string) error   { return status.Error(codes.FailedPrecondition, message) }

// VoiceService is optional: constructing a client neither grants access nor
// enables native voice. All ownership comes from the authenticated connection.
type VoiceService interface {
	CreatePlaybackJob(context.Context, CreatePlaybackJobRequest) (PlaybackSnapshot, error)
	StreamPlayback(context.Context) (PlaybackStream, error)
	PausePlaybackJob(context.Context, JobRequest) (PlaybackSnapshot, error)
	ResumePlaybackJob(context.Context, JobRequest) (PlaybackSnapshot, error)
	CancelPlaybackJob(context.Context, JobRequest) (PlaybackSnapshot, error)
	GetPlaybackQueue(context.Context, PlaybackQueueRequest) (PlaybackQueue, error)
	SubscribeVoice(context.Context, SubscribeVoiceRequest) (VoiceReceiveStream, error)
	UnsubscribeVoice(context.Context, UnsubscribeVoiceRequest) (VoiceSubscriptionSnapshot, error)
}

// PlaybackStream supports one concurrent Send (or CloseSend) and one Recv.
// Send never queues producer data and is not an acceptance acknowledgement.
// Callers must Recv concurrently to obtain cumulative frame AND byte credits.
// Cancel the opening context to abandon a stream; it never rebinds or replays.
type PlaybackStream interface {
	Send(PlaybackInput) error
	Recv() (PlaybackSnapshot, error)
	// EndInput must precede CloseSend. Continue Recv until the terminal snapshot.
	CloseSend() error
}
type VoiceReceiveStream interface {
	Recv() (VoiceReceiveEvent, error)
}

type VoiceClient struct{ voice wire.VoiceServiceClient }

var _ VoiceService = (*VoiceClient)(nil)

func NewVoiceClient(conn grpc.ClientConnInterface) (*VoiceClient, error) {
	if conn == nil {
		return nil, clientInvalid()
	}
	return &VoiceClient{voice: wire.NewVoiceServiceClient(conn)}, nil
}
func (c *VoiceClient) CreatePlaybackJob(ctx context.Context, req CreatePlaybackJobRequest) (PlaybackSnapshot, error) {
	if err := clientContext(ctx); err != nil {
		return PlaybackSnapshot{}, err
	}
	if req.GuildID == "" || req.ChannelID == "" || req.Lifetime <= 0 || req.Format != Opus48kHz20ms {
		return PlaybackSnapshot{}, voiceInvalid("guild, channel, positive lifetime and OPUS_48KHZ_20MS are required")
	}
	v, err := c.voice.CreatePlaybackJob(core.HelperContext(ctx), &wire.CreatePlaybackJobRequest{GuildId: req.GuildID, ChannelId: req.ChannelID, Priority: req.Priority, Lifetime: durationpb.New(req.Lifetime), Format: req.Format})
	if err != nil {
		return PlaybackSnapshot{}, voiceRPCError(err)
	}
	return playbackSnapshot(v)
}
func (c *VoiceClient) PausePlaybackJob(ctx context.Context, req JobRequest) (PlaybackSnapshot, error) {
	return c.control(ctx, req, c.voice.PausePlaybackJob)
}
func (c *VoiceClient) ResumePlaybackJob(ctx context.Context, req JobRequest) (PlaybackSnapshot, error) {
	return c.control(ctx, req, c.voice.ResumePlaybackJob)
}
func (c *VoiceClient) CancelPlaybackJob(ctx context.Context, req JobRequest) (PlaybackSnapshot, error) {
	return c.control(ctx, req, c.voice.CancelPlaybackJob)
}
func (c *VoiceClient) control(ctx context.Context, req JobRequest, call func(context.Context, *wire.JobRequest, ...grpc.CallOption) (*wire.PlaybackSnapshot, error)) (PlaybackSnapshot, error) {
	if err := clientContext(ctx); err != nil {
		return PlaybackSnapshot{}, err
	}
	if req.JobID == "" {
		return PlaybackSnapshot{}, voiceInvalid("job ID is required")
	}
	v, err := call(core.HelperContext(ctx), &wire.JobRequest{JobId: string(req.JobID)})
	if err != nil {
		return PlaybackSnapshot{}, voiceRPCError(err)
	}
	s, err := playbackSnapshot(v)
	if err == nil && s.JobID != req.JobID {
		err = voiceProtocol("job ID changed")
	}
	return s, err
}
func (c *VoiceClient) GetPlaybackQueue(ctx context.Context, req PlaybackQueueRequest) (PlaybackQueue, error) {
	if err := clientContext(ctx); err != nil {
		return PlaybackQueue{}, err
	}
	if req.GuildID == "" || req.Limit == 0 {
		return PlaybackQueue{}, voiceInvalid("guild and positive queue limit are required")
	}
	v, err := c.voice.GetPlaybackQueue(core.HelperContext(ctx), &wire.PlaybackQueueRequest{GuildId: req.GuildID, Limit: req.Limit, Continuation: req.Continuation})
	if err != nil {
		return PlaybackQueue{}, voiceRPCError(err)
	}
	if v == nil || uint64(len(v.Jobs)) > uint64(req.Limit) {
		return PlaybackQueue{}, voiceProtocol("queue exceeds requested bound")
	}
	out := PlaybackQueue{Jobs: make([]PlaybackSnapshot, len(v.Jobs)), NextContinuation: v.NextContinuation}
	for i, job := range v.Jobs {
		out.Jobs[i], err = playbackSnapshot(job)
		if err != nil {
			return PlaybackQueue{}, err
		}
		if out.Jobs[i].GuildID != req.GuildID {
			return PlaybackQueue{}, voiceProtocol("queue guild changed")
		}
	}
	return out, nil
}
func voiceTime(v *timestamppb.Timestamp) (time.Time, error) {
	if v == nil {
		return time.Time{}, voiceProtocol("missing timestamp")
	}
	if err := v.CheckValid(); err != nil {
		return time.Time{}, voiceProtocol("invalid timestamp")
	}
	return v.AsTime(), nil
}
func playbackSnapshot(v *wire.PlaybackSnapshot) (PlaybackSnapshot, error) {
	if v == nil || v.JobId == "" || v.GuildId == "" || v.ChannelId == "" || v.State < PlaybackQueued || v.State > PlaybackFailed {
		return PlaybackSnapshot{}, voiceProtocol("missing playback identity or state")
	}
	if v.LastUdpWrittenSequence > v.LastSubmittedSequence || v.LastSubmittedSequence > v.LastAcceptedSequence || v.CreditThroughSequence < v.LastAcceptedSequence || (v.InputEnded && v.FinalSequence != v.LastAcceptedSequence) {
		return PlaybackSnapshot{}, voiceProtocol("inconsistent playback cursors")
	}
	if v.State == PlaybackCompleted && (!v.InputEnded || v.LastUdpWrittenSequence != v.FinalSequence) {
		return PlaybackSnapshot{}, voiceProtocol("completion without final UDP receipt")
	}
	expires, err := voiceTime(v.ExpiresAt)
	if err != nil {
		return PlaybackSnapshot{}, err
	}
	return PlaybackSnapshot{JobID: JobID(v.JobId), GuildID: v.GuildId, ChannelID: v.ChannelId, Priority: v.Priority, State: v.State, Reason: v.Reason, LastAcceptedSequence: v.LastAcceptedSequence, LastSubmittedSequence: v.LastSubmittedSequence, LastUDPWrittenSequence: v.LastUdpWrittenSequence, InputEnded: v.InputEnded, FinalSequence: v.FinalSequence, CreditThroughSequence: v.CreditThroughSequence, CreditThroughBytes: v.CreditThroughBytes, ExpiresAt: expires, TerminalError: voiceError(v.TerminalError)}, nil
}

func (c *VoiceClient) StreamPlayback(ctx context.Context) (PlaybackStream, error) {
	if err := clientContext(ctx); err != nil {
		return nil, err
	}
	streamCtx, cancel := context.WithCancel(core.HelperContext(ctx))
	stream, err := c.voice.StreamPlayback(streamCtx)
	if err != nil {
		cancel()
		return nil, voiceRPCError(err)
	}
	return &playbackStream{wire: stream, ctx: streamCtx, cancel: cancel}, nil
}

type playbackStream struct {
	wire                          grpc.BidiStreamingClient[wire.PlaybackInput, wire.PlaybackSnapshot]
	ctx                           context.Context
	cancel                        context.CancelFunc
	sendMu, recvMu, mu            sync.Mutex
	job                           JobID
	sequence, bytes               uint64
	ended, closed, terminal, seen bool
	sendErr                       error
	last                          PlaybackSnapshot
}

func (s *playbackStream) Send(input PlaybackInput) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if err := clientContext(s.ctx); err != nil {
		return err
	}
	s.mu.Lock()
	out, err := s.inputLocked(input)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	err = s.wire.Send(out)
	if err != nil {
		s.mu.Lock()
		s.sendErr = err
		s.mu.Unlock()
	}
	return voiceRPCError(err)
}
func (s *playbackStream) inputLocked(input PlaybackInput) (*wire.PlaybackInput, error) {
	if s.sendErr != nil {
		return nil, voiceState("failed input cannot be retried")
	}
	if s.terminal || s.closed || s.ended {
		return nil, voiceState("playback input has ended")
	}
	parts := 0
	if input.Bind != nil {
		parts++
	}
	if input.Frame != nil {
		parts++
	}
	if input.EndInput != nil {
		parts++
	}
	if parts != 1 {
		return nil, voiceInvalid("exactly one playback input is required")
	}
	if s.job == "" {
		if input.Bind == nil || input.Bind.JobID == "" {
			return nil, voiceState("first playback input must bind a job")
		}
		s.job = input.Bind.JobID
		return &wire.PlaybackInput{Part: &wire.PlaybackInput_Bind{Bind: &wire.JobRequest{JobId: string(s.job)}}}, nil
	}
	if input.Bind != nil {
		return nil, voiceState("producer cannot rebind")
	}
	if frame := input.Frame; frame != nil {
		if s.sequence == math.MaxUint64 || frame.Sequence != s.sequence+1 || len(frame.Opus) == 0 {
			return nil, voiceInvalid("nonempty sequential Opus frame required")
		}
		n := uint64(len(frame.Opus))
		if n > math.MaxUint64-s.bytes {
			return nil, voiceInvalid("cumulative Opus bytes exhausted")
		}
		if frame.Sequence > s.last.CreditThroughSequence || s.bytes+n > s.last.CreditThroughBytes {
			return nil, voiceInvalid("wait for both frame and byte credit before sending")
		}
		s.sequence = frame.Sequence
		s.bytes += n
		return &wire.PlaybackInput{Part: &wire.PlaybackInput_Frame{Frame: &wire.OpusFrame{Sequence: frame.Sequence, Opus: frame.Opus}}}, nil
	}
	if input.EndInput.FinalSequence != s.sequence {
		return nil, voiceInvalid("final sequence must equal last sent sequence")
	}
	s.ended = true
	return &wire.PlaybackInput{Part: &wire.PlaybackInput_EndInput{EndInput: &wire.PlaybackEnd{FinalSequence: s.sequence}}}, nil
}
func (s *playbackStream) CloseSend() error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.mu.Lock()
	if !s.ended {
		s.mu.Unlock()
		return voiceState("EndInput must precede half-close")
	}
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	return voiceRPCError(s.wire.CloseSend())
}
func (s *playbackStream) Recv() (PlaybackSnapshot, error) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	s.mu.Lock()
	terminal := s.terminal
	s.mu.Unlock()
	if terminal {
		return PlaybackSnapshot{}, io.EOF
	}
	v, err := s.wire.Recv()
	if err != nil {
		s.cancel()
		if errors.Is(err, io.EOF) {
			return PlaybackSnapshot{}, io.ErrUnexpectedEOF
		}
		return PlaybackSnapshot{}, voiceRPCError(err)
	}
	current, err := playbackSnapshot(v)
	if err != nil {
		s.cancel()
		return PlaybackSnapshot{}, err
	}
	s.mu.Lock()
	previous := s.last
	if current.JobID != s.job || current.LastAcceptedSequence > s.sequence || current.CreditThroughBytes < s.bytes || (current.InputEnded && (!s.ended || current.FinalSequence != s.sequence)) {
		err = voiceProtocol("response exceeds bound producer input")
	} else if s.seen && (current.GuildID != previous.GuildID || current.ChannelID != previous.ChannelID || current.Priority != previous.Priority || !current.ExpiresAt.Equal(previous.ExpiresAt) || current.LastAcceptedSequence < previous.LastAcceptedSequence || current.LastSubmittedSequence < previous.LastSubmittedSequence || current.LastUDPWrittenSequence < previous.LastUDPWrittenSequence || current.CreditThroughSequence < previous.CreditThroughSequence || current.CreditThroughBytes < previous.CreditThroughBytes || (previous.InputEnded && !current.InputEnded)) {
		err = voiceProtocol("playback identity or cumulative cursor regressed")
	}
	if err == nil {
		s.last = current
		s.seen = true
		s.terminal = current.Terminal()
	}
	s.mu.Unlock()
	if err != nil || current.Terminal() {
		s.cancel()
	}
	return current, err
}

// ProducePlayback binds one producer and runs its sender and receiver together.
// maxPacketBytes is the producer's explicit finite upper bound. Before EACH next
// call (including the EOF read), both a frame slot and that many byte credits
// must be available. next must honor ctx, return one complete immutable Opus
// packet no larger than maxPacketBytes, and use io.EOF only for clean input end.
// There is at most one producer packet in memory, no pacing sleep, encoding,
// upload, retry, replay or automatic rebind. EOF sends EndInput then half-closes;
// successful return waits for the server's COMPLETED final UDP-write snapshot.
func (c *VoiceClient) ProducePlayback(ctx context.Context, req JobRequest, maxPacketBytes uint64, next func(context.Context) ([]byte, error)) (PlaybackSnapshot, error) {
	if err := clientContext(ctx); err != nil {
		return PlaybackSnapshot{}, err
	}
	if req.JobID == "" || maxPacketBytes == 0 || next == nil {
		return PlaybackSnapshot{}, voiceInvalid("job, finite packet bound and producer are required")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	public, err := c.StreamPlayback(ctx)
	if err != nil {
		return PlaybackSnapshot{}, err
	}
	s := public.(*playbackStream)
	if err := s.Send(PlaybackInput{Bind: &req}); err != nil {
		if !errors.Is(err, io.EOF) {
			return PlaybackSnapshot{}, err
		}
		for {
			value, recvErr := s.Recv()
			if recvErr != nil {
				return value, recvErr
			}
			if value.Terminal() {
				return value, playbackTerminalError(value)
			}
		}
	}
	var resultMu sync.Mutex
	var last PlaybackSnapshot
	var recvErr error
	notify := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		for {
			value, err := s.Recv()
			resultMu.Lock()
			if err == nil {
				last = value
			} else {
				recvErr = err
			}
			resultMu.Unlock()
			select {
			case notify <- struct{}{}:
			default:
			}
			if err != nil || value.Terminal() {
				return
			}
		}
	}()
	defer func() { cancel(); <-done }()
	result := func() (PlaybackSnapshot, error) {
		resultMu.Lock()
		defer resultMu.Unlock()
		if last.Terminal() {
			return last, playbackTerminalError(last)
		}
		if recvErr != nil {
			return last, recvErr
		}
		return last, status.FromContextError(ctx.Err()).Err()
	}
	sequence, totalBytes := uint64(0), uint64(0)
	for {
		if sequence == math.MaxUint64 || maxPacketBytes > math.MaxUint64-totalBytes {
			return lastProducerSnapshot(s), voiceInvalid("producer sequence or byte counter exhausted")
		}
		for {
			select {
			case <-done:
				return result()
			default:
			}
			s.mu.Lock()
			credit := !s.terminal && sequence < math.MaxUint64 && sequence+1 <= s.last.CreditThroughSequence && totalBytes <= s.last.CreditThroughBytes && maxPacketBytes <= s.last.CreditThroughBytes-totalBytes
			s.mu.Unlock()
			if credit {
				break
			}
			select {
			case <-notify:
			case <-ctx.Done():
				return result()
			}
		}
		if s.ctx.Err() != nil {
			<-done
			return result()
		}
		packet, readErr := next(s.ctx)
		if s.ctx.Err() != nil {
			<-done
			return result()
		}
		if readErr != nil && (!errors.Is(readErr, io.EOF) || len(packet) != 0) {
			if errors.Is(readErr, io.EOF) {
				readErr = io.ErrUnexpectedEOF
			}
			return lastProducerSnapshot(s), readErr
		}
		if errors.Is(readErr, io.EOF) {
			err = s.Send(PlaybackInput{EndInput: &PlaybackEnd{FinalSequence: sequence}})
			if err == nil {
				err = s.CloseSend()
			}
			if err != nil && !errors.Is(err, io.EOF) && s.ctx.Err() == nil {
				return lastProducerSnapshot(s), err
			}
			select {
			case <-done:
				return result()
			case <-ctx.Done():
				<-done
				return result()
			}
		}
		if len(packet) == 0 || uint64(len(packet)) > maxPacketBytes {
			return lastProducerSnapshot(s), voiceInvalid("producer packet violates its declared bound")
		}
		sequence++
		err = s.Send(PlaybackInput{Frame: &OpusFrame{Sequence: sequence, Opus: packet}})
		if err != nil {
			if errors.Is(err, io.EOF) || s.ctx.Err() != nil {
				<-done
				return result()
			}
			return lastProducerSnapshot(s), err
		}
		totalBytes += uint64(len(packet))
	}
}
func lastProducerSnapshot(s *playbackStream) PlaybackSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}
func playbackTerminalError(s PlaybackSnapshot) error {
	if s.TerminalError != nil {
		return s.TerminalError
	}
	if s.State == PlaybackCompleted {
		return nil
	}
	code := codes.Internal
	if s.State == PlaybackCancelled {
		code = codes.Canceled
	}
	return &VoiceError{Code: code, Reason: wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE, Stage: wire.VoiceFailureStage_VOICE_FAILURE_STAGE_INPUT, Message: "playback ended without completion", GuildID: s.GuildID, ChannelID: s.ChannelID, JobID: s.JobID, MayHaveSubmitted: s.LastSubmittedSequence != 0}
}

func subscriptionSnapshot(v *wire.VoiceSubscriptionSnapshot) (VoiceSubscriptionSnapshot, error) {
	if v == nil || v.SubscriptionId == "" || v.GuildId == "" || v.ChannelId == "" || v.State < SubscriptionJoining || v.State > SubscriptionFailed {
		return VoiceSubscriptionSnapshot{}, voiceProtocol("missing subscription identity or state")
	}
	expires, err := voiceTime(v.ExpiresAt)
	if err != nil {
		return VoiceSubscriptionSnapshot{}, err
	}
	return VoiceSubscriptionSnapshot{SubscriptionID: SubscriptionID(v.SubscriptionId), GuildID: v.GuildId, ChannelID: v.ChannelId, State: v.State, ExpiresAt: expires, TerminalError: voiceError(v.TerminalError)}, nil
}
func (c *VoiceClient) SubscribeVoice(ctx context.Context, req SubscribeVoiceRequest) (VoiceReceiveStream, error) {
	if err := clientContext(ctx); err != nil {
		return nil, err
	}
	if req.GuildID == "" || req.ChannelID == "" || req.Lifetime <= 0 {
		return nil, voiceInvalid("guild, channel and positive lifetime are required")
	}
	streamCtx, cancel := context.WithCancel(core.HelperContext(ctx))
	stream, err := c.voice.SubscribeVoice(streamCtx, &wire.SubscribeVoiceRequest{GuildId: req.GuildID, ChannelId: req.ChannelID, Lifetime: durationpb.New(req.Lifetime), Ssrcs: req.SSRCs})
	if err != nil {
		cancel()
		return nil, voiceRPCError(err)
	}
	return &voiceReceiveStream{wire: stream, cancel: cancel, guild: req.GuildID, channel: req.ChannelID}, nil
}
func (c *VoiceClient) UnsubscribeVoice(ctx context.Context, req UnsubscribeVoiceRequest) (VoiceSubscriptionSnapshot, error) {
	if err := clientContext(ctx); err != nil {
		return VoiceSubscriptionSnapshot{}, err
	}
	if req.SubscriptionID == "" {
		return VoiceSubscriptionSnapshot{}, voiceInvalid("subscription ID is required")
	}
	v, err := c.voice.UnsubscribeVoice(core.HelperContext(ctx), &wire.UnsubscribeVoiceRequest{SubscriptionId: string(req.SubscriptionID)})
	if err != nil {
		return VoiceSubscriptionSnapshot{}, voiceRPCError(err)
	}
	s, err := subscriptionSnapshot(v)
	if err == nil && (s.SubscriptionID != req.SubscriptionID || (s.State != SubscriptionClosed && s.State != SubscriptionFailed)) {
		err = voiceProtocol("unsubscribe did not return the owned terminal record")
	}
	return s, err
}

type voiceReceiveStream struct {
	wire           grpc.ServerStreamingClient[wire.VoiceReceiveEvent]
	cancel         context.CancelFunc
	mu             sync.Mutex
	guild, channel string
	last           VoiceSubscriptionSnapshot
	sequence       uint64
	terminal       bool
}

func (s *voiceReceiveStream) Recv() (VoiceReceiveEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal {
		return VoiceReceiveEvent{}, io.EOF
	}
	v, err := s.wire.Recv()
	if err != nil {
		s.cancel()
		if errors.Is(err, io.EOF) {
			return VoiceReceiveEvent{}, io.ErrUnexpectedEOF
		}
		return VoiceReceiveEvent{}, voiceRPCError(err)
	}
	out, err := s.event(v)
	if err != nil || s.terminal {
		s.cancel()
	}
	return out, err
}
func (s *voiceReceiveStream) event(v *wire.VoiceReceiveEvent) (VoiceReceiveEvent, error) {
	if v == nil {
		return VoiceReceiveEvent{}, voiceProtocol("missing receive event")
	}
	if packet, ok := v.Event.(*wire.VoiceReceiveEvent_Packet); ok {
		p := packet.Packet
		if p == nil || s.last.State != SubscriptionActive || SubscriptionID(p.SubscriptionId) != s.last.SubscriptionID || p.ReceiveSequence <= s.sequence || p.RtpSequence > math.MaxUint16 || len(p.Opus) == 0 {
			return VoiceReceiveEvent{}, voiceProtocol("packet before ACTIVE or invalid packet identity/sequence")
		}
		received, err := voiceTime(p.ReceivedAt)
		if err != nil {
			return VoiceReceiveEvent{}, err
		}
		s.sequence = p.ReceiveSequence
		return VoiceReceiveEvent{Packet: &VoicePacket{SubscriptionID: s.last.SubscriptionID, SSRC: p.Ssrc, RTPSequence: p.RtpSequence, RTPTimestamp: p.RtpTimestamp, ReceiveSequence: p.ReceiveSequence, ReceivedAt: received, Opus: p.Opus}}, nil
	}
	var raw *wire.VoiceSubscriptionSnapshot
	terminal := false
	switch part := v.Event.(type) {
	case *wire.VoiceReceiveEvent_Ready:
		raw = part.Ready
	case *wire.VoiceReceiveEvent_Terminal:
		raw = part.Terminal
		terminal = true
	default:
		return VoiceReceiveEvent{}, voiceProtocol("missing receive event alternative")
	}
	current, err := subscriptionSnapshot(raw)
	if err != nil {
		return VoiceReceiveEvent{}, err
	}
	if current.GuildID != s.guild || current.ChannelID != s.channel {
		return VoiceReceiveEvent{}, voiceProtocol("subscription channel changed")
	}
	if s.last.SubscriptionID == "" {
		if terminal || current.State != SubscriptionJoining {
			return VoiceReceiveEvent{}, voiceProtocol("first receive event must be JOINING")
		}
	} else {
		if current.SubscriptionID != s.last.SubscriptionID || !current.ExpiresAt.Equal(s.last.ExpiresAt) {
			return VoiceReceiveEvent{}, voiceProtocol("subscription identity changed")
		}
		if terminal {
			if current.State != SubscriptionClosed && current.State != SubscriptionFailed {
				return VoiceReceiveEvent{}, voiceProtocol("invalid terminal subscription state")
			}
		} else if s.last.State != SubscriptionJoining || current.State != SubscriptionActive {
			return VoiceReceiveEvent{}, voiceProtocol("expected distinct ACTIVE readiness event")
		}
	}
	s.last = current
	s.terminal = terminal
	if terminal {
		return VoiceReceiveEvent{Terminal: &current}, nil
	}
	return VoiceReceiveEvent{Ready: &current}, nil
}
