package voicejobs

import (
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/grpc/codes"
	"time"
)

// controlJob runs on the guild actor. Deferred replies retain only a bounded,
// buffered response slot; an expired RPC never blocks the sender's receipt lane.
func (g *guild) controlJob(id, operation string, reply chan answer) (any, error) {
	j := g.jobs[id]
	if j == nil {
		return nil, notFound()
	}
	switch operation {
	case "PausePlaybackJob":
		if j.stopping != nil {
			return nil, failure(codes.FailedPrecondition, wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONTROL)
		}
		if j.paused {
			return snapshot(j), nil
		}
		if g.inflight == j {
			if len(j.waiters) >= g.service.config.ControlMailbox {
				return nil, quota()
			}
			j.pausing = true
			j.idleSince = time.Time{}
			j.waiters = append(j.waiters, reply)
			return nil, errDeferred
		}
		j.paused = true
		j.pausing = false
		j.idleSince = time.Time{}
		g.setState(j, wire.PlaybackState_PLAYBACK_STATE_PAUSED, wire.PlaybackReason_PLAYBACK_REASON_OWNER_PAUSED)
	case "ResumePlaybackJob":
		if j.stopping != nil {
			return nil, failure(codes.FailedPrecondition, wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONTROL)
		}
		// A resume overlapping an unapplied pause sees the current running state.
		// It must not remove that pause's receipt waiter or promise to undo it.
		if !j.paused {
			return snapshot(j), nil
		}
		j.paused = false
		j.pausing = false
		g.setState(j, wire.PlaybackState_PLAYBACK_STATE_QUEUED, wire.PlaybackReason_PLAYBACK_REASON_WAITING_PRIORITY)
	case "CancelPlaybackJob":
		if g.inflight == j {
			if len(j.waiters) >= g.service.config.ControlMailbox {
				return nil, quota()
			}
			j.waiters = append(j.waiters, reply)
			g.stopJob(j, failure(codes.Canceled, wire.VoiceErrorReason_VOICE_ERROR_REASON_OWNER_CANCELLED, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONTROL), true)
			return nil, errDeferred
		}
		g.stopJob(j, failure(codes.Canceled, wire.VoiceErrorReason_VOICE_ERROR_REASON_OWNER_CANCELLED, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONTROL), true)
	default:
		return nil, failure(codes.Internal, wire.VoiceErrorReason_VOICE_ERROR_REASON_INTERNAL, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONTROL)
	}
	return snapshot(j), nil
}
