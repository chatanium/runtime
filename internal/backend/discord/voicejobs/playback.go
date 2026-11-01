package voicejobs

import (
	"io"
	"math"
	"time"

	"github.com/bwmarrin/discordgo"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
)

type inputResult struct {
	input *wire.PlaybackInput
	err   error
}

func (h *server) StreamPlayback(stream grpc.BidiStreamingServer[wire.PlaybackInput, wire.PlaybackSnapshot]) error {
	ctx := stream.Context()
	p, done, err := h.begin(ctx, "StreamPlayback")
	if err != nil {
		return err
	}
	defer done()
	incoming := make(chan inputResult)
	stop := make(chan struct{})
	defer close(stop)
	life, err := h.service.instanceLifetime(p)
	if err != nil {
		return err
	}
	advance := make(chan struct{}, 1)
	go func() {
		for {
			m, e := stream.Recv()
			select {
			case incoming <- inputResult{m, e}:
			case <-stop:
				return
			case <-ctx.Done():
				return
			}
			if e != nil {
				return
			}
			select {
			case <-advance:
			case <-stop:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	timer := time.NewTimer(h.service.config.FirstBindTimeout)
	defer timer.Stop()
	var first inputResult
	select {
	case first = <-incoming:
	case <-ctx.Done():
		return ctx.Err()
	case <-life.Done():
		return stopped()
	case <-timer.C:
		return timeout(wire.VoiceErrorReason_VOICE_ERROR_REASON_BIND_TIMEOUT, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_BIND)
	}
	if first.err != nil {
		return invalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INPUT_TRUNCATED)
	}
	if first.input == nil || first.input.GetBind() == nil || proto.Size(first.input) > h.service.config.MaxGRPCMessageBytes {
		return invalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE)
	}
	ref, err := h.job(ctx, p, first.input.GetBind().JobId, "StreamPlayback")
	if err != nil {
		return err
	}
	if ref.final != nil {
		return failure(codes.FailedPrecondition, wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_BIND)
	}
	value, err := ref.actor.ask(ctx, func(g *guild) (any, error) { return g.bind(first.input.GetBind().JobId) })
	if err != nil {
		return err
	}
	j := value.(*job)
	advance <- struct{}{}
	cause := failure(codes.Canceled, wire.VoiceErrorReason_VOICE_ERROR_REASON_STREAM_CANCELLED, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_INPUT)
	defer func() {
		if life.Err() != nil {
			cause = stopped()
		}
		ref.actor.post(func(g *guild) (any, error) {
			j.streamEnded = true
			if active := g.jobs[j.id]; active != nil {
				g.stopJob(active, cause, codes.Code(cause.detail.GrpcCode) == codes.Canceled)
			}
			if terminal(j.snapshot.State) {
				g.releaseStatus(j)
			}
			return nil, nil
		})
		select {
		case <-j.terminalDone:
			ref.actor.releaseStatus(j)
		default:
		}
	}()
	outgoing := make(chan error, 1)
	go func() {
		for {
			select {
			case snapshot := <-j.status:
				alarm := time.AfterFunc(h.service.config.SlowConsumerTimeout, func() {
					select {
					case outgoing <- timeout(wire.VoiceErrorReason_VOICE_ERROR_REASON_RECEIVE_TIMEOUT, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONTROL):
					default:
					}
				})
				e := stream.Send(snapshot)
				fired := !alarm.Stop()
				if fired {
					return
				}
				if e != nil {
					select {
					case outgoing <- e:
					default:
					}
					return
				}
				if terminal(snapshot.State) {
					select {
					case outgoing <- nil:
					default:
					}
					return
				}
			case <-stop:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	input := incoming
	for {
		select {
		case message := <-input:
			if message.err == io.EOF {
				e := ref.actor.call(ctx, func(g *guild) (any, error) { g.inputEOF(j.id); return nil, nil })
				if e != nil {
					return e
				}
				input = nil
				continue
			}
			if message.err != nil {
				cause = streamFailure(message.err)
				return message.err
			}
			_, e := ref.actor.ask(ctx, func(g *guild) (any, error) {
				active := g.jobs[j.id]
				if active == nil {
					return nil, failure(codes.FailedPrecondition, wire.VoiceErrorReason_VOICE_ERROR_REASON_INPUT_AFTER_END, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_INPUT)
				}
				if err := g.accept(active, message.input); err != nil {
					v, ok := err.(*voiceFailure)
					if !ok {
						v = failure(codes.InvalidArgument, wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_OPUS, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_INPUT)
					}
					g.stopJob(active, v, false)
				}
				return nil, nil
			})
			if e != nil {
				return e
			}
			advance <- struct{}{}
		case err := <-outgoing:
			if err != nil {
				cause = streamFailure(err)
			}
			return err
		case <-ctx.Done():
			cause = streamFailure(ctx.Err())
			return ctx.Err()
		case <-life.Done():
			return stopped()
		}
	}
}
func (g *guild) accept(j *job, input *wire.PlaybackInput) error {
	if input == nil || proto.Size(input) > g.service.config.MaxGRPCMessageBytes {
		return invalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE)
	}
	if j.snapshot.InputEnded || j.stopping != nil {
		return invalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INPUT_AFTER_END)
	}
	switch part := input.Part.(type) {
	case *wire.PlaybackInput_Frame:
		f := part.Frame
		if f == nil {
			return invalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_OPUS)
		}
		if j.snapshot.LastAcceptedSequence == math.MaxUint64 {
			return invalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_SEQUENCE_EXHAUSTED)
		}
		if f.Sequence != j.snapshot.LastAcceptedSequence+1 {
			return invalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_SEQUENCE)
		}
		if uint64(len(f.Opus)) > math.MaxUint64-j.acceptedBytes || f.Sequence > j.snapshot.CreditThroughSequence || j.acceptedBytes+uint64(len(f.Opus)) > j.snapshot.CreditThroughBytes {
			return invalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_CREDIT_EXCEEDED)
		}
		if err := discordgo.ValidateOpusPacket(f.Opus, g.service.config.MaxOpusPacketBytes); err != nil {
			return invalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_OPUS)
		}
		// gRPC Recv owns this decoded message; move its byte storage into the actor.
		// No caller in another process retains this slice, and it stays unchanged
		// until the sender's receipt releases the sole in-flight owner.
		if j.frames.count == len(j.frames.slots) {
			return invalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_CREDIT_EXCEEDED)
		}
		owned := f.Opus
		f.Opus = nil
		j.frames.push(frame{sequence: f.Sequence, opus: owned})
		j.snapshot.LastAcceptedSequence = f.Sequence
		j.acceptedBytes += uint64(len(owned))
		j.idleSince = time.Time{}
		g.publish(j)
		return nil
	case *wire.PlaybackInput_EndInput:
		if part.EndInput == nil || part.EndInput.FinalSequence != j.snapshot.LastAcceptedSequence {
			return invalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_FINAL_SEQUENCE)
		}
		j.snapshot.InputEnded = true
		j.snapshot.FinalSequence = part.EndInput.FinalSequence
		j.idleSince = time.Time{}
		g.publish(j)
		if g.inflight != j && j.frames.count == 0 {
			g.finishCompleted(j)
		}
		return nil
	default:
		return invalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE)
	}
}
func (g *guild) releaseStatus(j *job) {
	j.statusRelease.Do(func() {
		s := g.service
		s.mu.Lock()
		s.statusBytes -= s.config.StatusMailboxBytes
		s.signalLocked()
		s.mu.Unlock()
	})
}
func (g *guild) bind(id string) (*job, error) {
	j := g.jobs[id]
	if j == nil {
		return nil, notFound()
	}
	if j.bound {
		return nil, failure(codes.FailedPrecondition, wire.VoiceErrorReason_VOICE_ERROR_REASON_PRODUCER_ALREADY_BOUND, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_BIND)
	}
	if j.stopping != nil {
		return nil, failure(codes.FailedPrecondition, wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_BIND)
	}
	j.bound = true
	g.publish(j)
	return j, nil
}
func (g *guild) inputEOF(id string) {
	if j := g.jobs[id]; j != nil && !j.snapshot.InputEnded {
		g.stopJob(j, failure(codes.InvalidArgument, wire.VoiceErrorReason_VOICE_ERROR_REASON_INPUT_TRUNCATED, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_INPUT), false)
	}
}
