package discordv2

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// These are adversarial protocol fixtures, not echo helpers: each server owns
// credits, acceptance, half-close and terminal timing independently of Send.
// The real generated client and gRPC serialization are used in every fixture.
type voiceFixture struct {
	wire.UnimplementedVoiceServiceServer
	play    func(grpc.BidiStreamingServer[wire.PlaybackInput, wire.PlaybackSnapshot]) error
	receive func(*wire.SubscribeVoiceRequest, grpc.ServerStreamingServer[wire.VoiceReceiveEvent]) error
}

func (f *voiceFixture) StreamPlayback(s grpc.BidiStreamingServer[wire.PlaybackInput, wire.PlaybackSnapshot]) error {
	if f.play == nil {
		return status.Error(codes.Unimplemented, "unexpected playback")
	}
	return f.play(s)
}
func (f *voiceFixture) SubscribeVoice(r *wire.SubscribeVoiceRequest, s grpc.ServerStreamingServer[wire.VoiceReceiveEvent]) error {
	if f.receive == nil {
		return status.Error(codes.Unimplemented, "unexpected subscription")
	}
	return f.receive(r, s)
}
func voiceFixtureClient(t *testing.T, fixture *voiceFixture) (*VoiceClient, context.Context) {
	t.Helper()
	listener := bufconn.Listen(64 * 1024)
	server := grpc.NewServer()
	wire.RegisterVoiceServiceServer(server, fixture)
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///voice-fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		server.Stop()
		_ = listener.Close()
		t.Fatal(err)
	}
	client, err := NewVoiceClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(func() { cancel(); _ = conn.Close(); server.Stop(); _ = listener.Close() })
	return client, ctx
}
func fixturePlayback(state PlaybackState, accepted, submitted, written, frames, bytes uint64, ended bool) *wire.PlaybackSnapshot {
	return &wire.PlaybackSnapshot{JobId: "job", GuildId: "guild", ChannelId: "channel", State: state, LastAcceptedSequence: accepted, LastSubmittedSequence: submitted, LastUdpWrittenSequence: written, InputEnded: ended, FinalSequence: accepted, CreditThroughSequence: frames, CreditThroughBytes: bytes, ExpiresAt: timestamppb.New(time.Unix(2000000000, 0))}
}
func fixtureBind(s grpc.BidiStreamingServer[wire.PlaybackInput, wire.PlaybackSnapshot]) error {
	v, err := s.Recv()
	if err != nil {
		return err
	}
	if v.GetBind().GetJobId() != "job" {
		return status.Error(codes.InvalidArgument, "expected sole initial bind")
	}
	return nil
}
func waitVoiceSignal(t *testing.T, ctx context.Context, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
func assertVoiceNotSignaled(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	timer := time.NewTimer(50 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-signal:
		t.Fatal(message)
	case <-timer.C:
	}
}

type voiceProduceResult struct {
	snapshot PlaybackSnapshot
	err      error
}

func TestVoiceProducerWaitsForFrameAndWholePacketByteCredit(t *testing.T) {
	frameCredit := make(chan struct{})
	byteCredit := make(chan struct{})
	initialSent := make(chan struct{})
	frameOnlySent := make(chan struct{})
	frameReceived := make(chan struct{})
	renewCredit := make(chan struct{})
	endReceived := make(chan struct{})
	receipt := make(chan struct{})
	fixture := &voiceFixture{play: func(s grpc.BidiStreamingServer[wire.PlaybackInput, wire.PlaybackSnapshot]) error {
		if err := fixtureBind(s); err != nil {
			return err
		}
		// Byte credit alone is not permission to read the encoder.
		if err := s.Send(fixturePlayback(PlaybackQueued, 0, 0, 0, 0, 3, false)); err != nil {
			return err
		}
		close(initialSent)
		select {
		case <-frameCredit:
		case <-s.Context().Done():
			return s.Context().Err()
		}
		// A frame slot with less than the declared packet bound is also insufficient.
		if err := s.Send(fixturePlayback(PlaybackQueued, 0, 0, 0, 1, 3, false)); err != nil {
			return err
		}
		close(frameOnlySent)
		select {
		case <-byteCredit:
		case <-s.Context().Done():
			return s.Context().Err()
		}
		if err := s.Send(fixturePlayback(PlaybackRunning, 0, 0, 0, 1, 4, false)); err != nil {
			return err
		}
		v, err := s.Recv()
		if err != nil {
			return err
		}
		if v.GetFrame().GetSequence() != 1 || len(v.GetFrame().GetOpus()) != 4 {
			return status.Error(codes.InvalidArgument, "expected exactly one bounded frame")
		}
		close(frameReceived)
		select {
		case <-renewCredit:
		case <-s.Context().Done():
			return s.Context().Err()
		}
		if err := s.Send(fixturePlayback(PlaybackRunning, 1, 1, 0, 2, 8, false)); err != nil {
			return err
		}
		v, err = s.Recv()
		if err != nil {
			return err
		}
		if v.GetEndInput() == nil || v.GetEndInput().GetFinalSequence() != 1 {
			return status.Error(codes.InvalidArgument, "missing explicit final sequence")
		}
		if _, err := s.Recv(); !errors.Is(err, io.EOF) {
			return status.Error(codes.InvalidArgument, "EndInput must be followed by half-close")
		}
		close(endReceived)
		// Acceptance/submission and input end are not local UDP completion.
		if err := s.Send(fixturePlayback(PlaybackRunning, 1, 1, 0, 2, 8, true)); err != nil {
			return err
		}
		select {
		case <-receipt:
		case <-s.Context().Done():
			return s.Context().Err()
		}
		return s.Send(fixturePlayback(PlaybackCompleted, 1, 1, 1, 2, 8, true))
	}}
	client, ctx := voiceFixtureClient(t, fixture)
	reads := make(chan struct{}, 4)
	results := make(chan voiceProduceResult, 1)
	go func() {
		calls := 0
		snapshot, err := client.ProducePlayback(ctx, JobRequest{JobID: "job"}, 4, func(context.Context) ([]byte, error) {
			reads <- struct{}{}
			calls++
			if calls == 1 {
				return []byte{1, 2, 3, 4}, nil
			}
			return nil, io.EOF
		})
		results <- voiceProduceResult{snapshot, err}
	}()
	waitVoiceSignal(t, ctx, initialSent)
	assertVoiceNotSignaled(t, reads, "encoder read without frame credit")
	close(frameCredit)
	waitVoiceSignal(t, ctx, frameOnlySent)
	assertVoiceNotSignaled(t, reads, "encoder read without whole-packet byte credit")
	close(byteCredit)
	waitVoiceSignal(t, ctx, reads)
	waitVoiceSignal(t, ctx, frameReceived)
	assertVoiceNotSignaled(t, reads, "producer prefetched another packet after exhausting credit")
	close(renewCredit)
	waitVoiceSignal(t, ctx, reads)
	waitVoiceSignal(t, ctx, endReceived)
	select {
	case result := <-results:
		t.Fatalf("producer returned before final UDP receipt: %+v", result)
	default:
	}
	close(receipt)
	select {
	case result := <-results:
		if result.err != nil || result.snapshot.State != PlaybackCompleted || result.snapshot.LastUDPWrittenSequence != 1 {
			t.Fatalf("missing completed receipt: %+v", result)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestVoicePlaybackExplicitEmptyEndVersusTruncatedEOF(t *testing.T) {
	t.Run("explicit empty input", func(t *testing.T) {
		client, ctx := voiceFixtureClient(t, &voiceFixture{play: func(s grpc.BidiStreamingServer[wire.PlaybackInput, wire.PlaybackSnapshot]) error {
			if err := fixtureBind(s); err != nil {
				return err
			}
			v, err := s.Recv()
			if err != nil {
				return err
			}
			if v.GetEndInput() == nil || v.GetEndInput().FinalSequence != 0 {
				return status.Error(codes.InvalidArgument, "empty job requires explicit EndInput(0)")
			}
			if _, err := s.Recv(); !errors.Is(err, io.EOF) {
				return status.Error(codes.InvalidArgument, "missing half-close")
			}
			return s.Send(fixturePlayback(PlaybackCompleted, 0, 0, 0, 0, 0, true))
		}})
		stream, err := client.StreamPlayback(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.CloseSend(); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("truncated half-close accepted: %v", err)
		}
		if err := stream.Send(PlaybackInput{Bind: &JobRequest{JobID: "job"}}); err != nil {
			t.Fatal(err)
		}
		if err := stream.Send(PlaybackInput{EndInput: &PlaybackEnd{FinalSequence: 0}}); err != nil {
			t.Fatal(err)
		}
		if err := stream.CloseSend(); err != nil {
			t.Fatal(err)
		}
		value, err := stream.Recv()
		if err != nil || value.State != PlaybackCompleted || value.FinalSequence != 0 {
			t.Fatalf("empty explicit end failed: %+v, %v", value, err)
		}
		if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
			t.Fatalf("missing EOF after terminal: %v", err)
		}
	})
	t.Run("server EOF without terminal", func(t *testing.T) {
		client, ctx := voiceFixtureClient(t, &voiceFixture{play: func(s grpc.BidiStreamingServer[wire.PlaybackInput, wire.PlaybackSnapshot]) error {
			return fixtureBind(s)
		}})
		stream, err := client.StreamPlayback(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.Send(PlaybackInput{Bind: &JobRequest{JobID: "job"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Recv(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("truncated response became success: %v", err)
		}
	})
}

func TestVoiceProducerCancellationUnblocksCreditAndReleasesStream(t *testing.T) {
	bound := make(chan struct{})
	released := make(chan struct{})
	client, parent := voiceFixtureClient(t, &voiceFixture{play: func(s grpc.BidiStreamingServer[wire.PlaybackInput, wire.PlaybackSnapshot]) error {
		defer close(released)
		if err := fixtureBind(s); err != nil {
			return err
		}
		if err := s.Send(fixturePlayback(PlaybackPaused, 0, 0, 0, 0, 0, false)); err != nil {
			return err
		}
		close(bound)
		<-s.Context().Done()
		return s.Context().Err()
	}})
	ctx, cancel := context.WithCancel(parent)
	var reads atomic.Int32
	results := make(chan voiceProduceResult, 1)
	go func() {
		snapshot, err := client.ProducePlayback(ctx, JobRequest{JobID: "job"}, 4, func(context.Context) ([]byte, error) { reads.Add(1); return nil, io.EOF })
		results <- voiceProduceResult{snapshot, err}
	}()
	waitVoiceSignal(t, parent, bound)
	cancel()
	select {
	case result := <-results:
		if status.Code(result.err) != codes.Canceled || reads.Load() != 0 {
			t.Fatalf("credit cancellation read or hid error: %+v, reads=%d", result, reads.Load())
		}
	case <-parent.Done():
		t.Fatal(parent.Err())
	}
	waitVoiceSignal(t, parent, released)
}

func TestVoiceProducerTerminalFailureInterruptsEncoder(t *testing.T) {
	reading := make(chan struct{})
	client, ctx := voiceFixtureClient(t, &voiceFixture{play: func(s grpc.BidiStreamingServer[wire.PlaybackInput, wire.PlaybackSnapshot]) error {
		if err := fixtureBind(s); err != nil {
			return err
		}
		if err := s.Send(fixturePlayback(PlaybackRunning, 0, 0, 0, 1, 4, false)); err != nil {
			return err
		}
		select {
		case <-reading:
		case <-s.Context().Done():
			return s.Context().Err()
		}
		failed := fixturePlayback(PlaybackFailed, 0, 0, 0, 1, 4, false)
		failed.TerminalError = &wire.VoiceError{GrpcCode: int32(codes.Unavailable), Reason: wire.VoiceErrorReason_VOICE_ERROR_REASON_CONNECTION_LOST, Stage: wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONNECTION, Message: "voice connection lost", JobId: "job"}
		return s.Send(failed)
	}})
	value, err := client.ProducePlayback(ctx, JobRequest{JobID: "job"}, 4, func(ctx context.Context) ([]byte, error) { close(reading); <-ctx.Done(); return nil, ctx.Err() })
	var detail *VoiceError
	if value.State != PlaybackFailed || !errors.As(err, &detail) || detail.Reason != wire.VoiceErrorReason_VOICE_ERROR_REASON_CONNECTION_LOST || status.Code(err) != codes.Unavailable {
		t.Fatalf("terminal failure lost to local cancellation: %+v, %v", value, err)
	}
}

func TestVoicePlaybackRejectsRebindGapsAndCreditViolation(t *testing.T) {
	client, ctx := voiceFixtureClient(t, &voiceFixture{play: func(s grpc.BidiStreamingServer[wire.PlaybackInput, wire.PlaybackSnapshot]) error {
		if err := fixtureBind(s); err != nil {
			return err
		}
		if err := s.Send(fixturePlayback(PlaybackQueued, 0, 0, 0, 1, 4, false)); err != nil {
			return err
		}
		<-s.Context().Done()
		return s.Context().Err()
	}})
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := client.StreamPlayback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(PlaybackInput{Frame: &OpusFrame{Sequence: 1, Opus: []byte{1}}}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("frame before bind accepted: %v", err)
	}
	if err := stream.Send(PlaybackInput{Bind: &JobRequest{JobID: "job"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	for _, input := range []PlaybackInput{
		{Bind: &JobRequest{JobID: "job"}},
		{Frame: &OpusFrame{Sequence: 2, Opus: []byte{1}}},
		{Frame: &OpusFrame{Sequence: 1, Opus: []byte{1, 2, 3, 4, 5}}},
		{EndInput: &PlaybackEnd{FinalSequence: 1}},
		{Bind: &JobRequest{JobID: "job"}, EndInput: &PlaybackEnd{}},
	} {
		if err := stream.Send(input); err == nil {
			t.Fatalf("invalid producer input accepted: %+v", input)
		}
	}
}

func fixtureSubscription(state SubscriptionState) *wire.VoiceSubscriptionSnapshot {
	return &wire.VoiceSubscriptionSnapshot{SubscriptionId: "subscription", GuildId: "guild", ChannelId: "channel", State: state, ExpiresAt: timestamppb.New(time.Unix(2000000000, 0))}
}
func fixtureReady(state SubscriptionState) *wire.VoiceReceiveEvent {
	return &wire.VoiceReceiveEvent{Event: &wire.VoiceReceiveEvent_Ready{Ready: fixtureSubscription(state)}}
}
func TestVoiceReceiveOnlyJoiningActivePacketAndExplicitTerminal(t *testing.T) {
	client, ctx := voiceFixtureClient(t, &voiceFixture{receive: func(_ *wire.SubscribeVoiceRequest, s grpc.ServerStreamingServer[wire.VoiceReceiveEvent]) error {
		for _, value := range []*wire.VoiceReceiveEvent{
			fixtureReady(SubscriptionJoining), fixtureReady(SubscriptionActive),
			{Event: &wire.VoiceReceiveEvent_Packet{Packet: &wire.VoicePacket{SubscriptionId: "subscription", Ssrc: 7, RtpSequence: 65535, RtpTimestamp: 960, ReceiveSequence: 1, ReceivedAt: timestamppb.New(time.Unix(1900000000, 0)), Opus: []byte{1, 2}}}},
			{Event: &wire.VoiceReceiveEvent_Terminal{Terminal: fixtureSubscription(SubscriptionClosed)}},
		} {
			if err := s.Send(value); err != nil {
				return err
			}
		}
		return nil
	}})
	stream, err := client.SubscribeVoice(ctx, SubscribeVoiceRequest{GuildID: "guild", ChannelID: "channel", Lifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []SubscriptionState{SubscriptionJoining, SubscriptionActive} {
		value, err := stream.Recv()
		if err != nil || value.Ready == nil || value.Ready.State != expected || value.Packet != nil || value.Terminal != nil {
			t.Fatalf("readiness collapsed: %+v, %v", value, err)
		}
	}
	packet, err := stream.Recv()
	if err != nil || packet.Packet == nil || packet.Packet.SubscriptionID != "subscription" || packet.Packet.RTPSequence != 65535 {
		t.Fatalf("missing authenticated packet envelope: %+v, %v", packet, err)
	}
	terminal, err := stream.Recv()
	if err != nil || terminal.Terminal == nil || terminal.Terminal.State != SubscriptionClosed {
		t.Fatalf("terminal event lost: %+v, %v", terminal, err)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("missing EOF after receive terminal: %v", err)
	}
}
func TestVoiceReceiveRejectsEarlyActiveAndTruncatedEOF(t *testing.T) {
	for _, early := range []bool{true, false} {
		t.Run(map[bool]string{true: "ACTIVE without JOINING", false: "EOF without terminal"}[early], func(t *testing.T) {
			client, ctx := voiceFixtureClient(t, &voiceFixture{receive: func(_ *wire.SubscribeVoiceRequest, s grpc.ServerStreamingServer[wire.VoiceReceiveEvent]) error {
				if early {
					return s.Send(fixtureReady(SubscriptionActive))
				}
				return nil
			}})
			stream, err := client.SubscribeVoice(ctx, SubscribeVoiceRequest{GuildID: "guild", ChannelID: "channel", Lifetime: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			_, err = stream.Recv()
			if early && status.Code(err) != codes.Internal {
				t.Fatalf("early ACTIVE accepted: %v", err)
			}
			if !early && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("truncated receive became success: %v", err)
			}
		})
	}
}
func TestVoiceReceiveContextCancellationReleasesOnlyItsStream(t *testing.T) {
	released := make(chan struct{})
	client, parent := voiceFixtureClient(t, &voiceFixture{receive: func(_ *wire.SubscribeVoiceRequest, s grpc.ServerStreamingServer[wire.VoiceReceiveEvent]) error {
		defer close(released)
		if err := s.Send(fixtureReady(SubscriptionJoining)); err != nil {
			return err
		}
		<-s.Context().Done()
		return s.Context().Err()
	}})
	ctx, cancel := context.WithCancel(parent)
	stream, err := client.SubscribeVoice(ctx, SubscribeVoiceRequest{GuildID: "guild", ChannelID: "channel", Lifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := stream.Recv(); status.Code(err) != codes.Canceled {
		t.Fatalf("receive cancellation hidden: %v", err)
	}
	waitVoiceSignal(t, parent, released)
}
