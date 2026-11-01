package voicejobs

import (
	"math"
	"time"

	rt "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/durationpb"
)

// createJob is called only after final authorization, on the guild's owner lane.
// WaitingJobs reserves a potential queued/paused position for every admitted
// job: a future preemption cannot overcommit the bounded waiting registry.
func (g *guild) createJob(owner rt.InstancePrincipal, id string, r *wire.CreatePlaybackJobRequest) (*wire.PlaybackSnapshot, error) {
	s := g.service
	s.mu.Lock()
	i := s.instances[owner.InstanceID]
	if i == nil || !i.active || i.draining || i.ctx.Err() != nil {
		s.mu.Unlock()
		return nil, failure(codes.FailedPrecondition, wire.VoiceErrorReason_VOICE_ERROR_REASON_DRAINING, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_ADMISSION)
	}
	retained := g.closingOwner == owner.InstanceID
	ownRetirement := g.retiring && g.closeStarted && !g.shutting && g.cleanupErr == nil && (retained || g.owners[owner.InstanceID] != 0)
	if g.closing && !ownRetirement || g.closingOwner != "" && !retained {
		s.mu.Unlock()
		return nil, failure(codes.FailedPrecondition, wire.VoiceErrorReason_VOICE_ERROR_REASON_CHANNEL_CONFLICT, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_ADMISSION)
	}
	if s.jobs[id] != nil {
		s.mu.Unlock()
		return nil, failure(codes.Internal, wire.VoiceErrorReason_VOICE_ERROR_REASON_INTERNAL, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_ADMISSION)
	}
	if i.usage.jobs >= s.config.InstanceJobs || s.usage.jobs >= s.config.HostJobs || s.usage.jobs >= s.config.WaitingJobs || len(g.jobs) >= s.config.GuildJobs || s.statusBytes > s.config.HostStatusBytes-s.config.StatusMailboxBytes || g.owners[owner.InstanceID] == 0 && !retained && i.usage.sessions >= s.config.InstanceSessions || s.ordinal == math.MaxUint64 {
		s.mu.Unlock()
		return nil, quota()
	}
	s.ordinal++
	ordinal := s.ordinal
	s.usage.jobs++
	i.usage.jobs++
	s.statusBytes += s.config.StatusMailboxBytes
	if g.owners[owner.InstanceID] == 0 {
		if retained {
			// Transfer the retiring owner's existing reservation without
			// overlapping sessions or bypassing another owner's quota.
			g.closingOwner = ""
		} else {
			i.usage.sessions++
		}
	}
	g.owners[owner.InstanceID]++
	s.jobs[id] = &jobRef{owner: owner, guild: g.id, channel: g.channel, actor: g, ordinal: ordinal}
	s.mu.Unlock()
	j := &job{id: id, owner: owner, ordinal: ordinal, snapshot: newSnapshot(id, g.id, g.channel, r.Priority, r.Lifetime.AsDuration()), status: make(chan *wire.PlaybackSnapshot, s.config.StatusMailbox), terminalDone: make(chan struct{}), firstBind: time.Now().Add(s.config.FirstBindTimeout), frames: frameQueue{slots: make([]frame, s.config.InitialCreditFrames)}}
	g.jobs[id] = j
	g.initialized = true
	g.finishRetirement()
	g.renew(j)
	g.publish(j)
	return snapshot(j), nil
}

type frameQueue struct {
	slots       []frame
	head, count int
}

func (q *frameQueue) push(v frame) { q.slots[(q.head+q.count)%len(q.slots)] = v; q.count++ }
func (q *frameQueue) pop() frame {
	v := q.slots[q.head]
	q.slots[q.head] = frame{}
	q.head = (q.head + 1) % len(q.slots)
	q.count--
	return v
}
func (q *frameQueue) clear() {
	for n := range q.slots {
		q.slots[n] = frame{}
	}
	q.head = 0
	q.count = 0
}
func (q *frameQueue) pushFront(v frame) {
	q.head = (q.head + len(q.slots) - 1) % len(q.slots)
	q.slots[q.head] = v
	q.count++
}
func validLifetime(v *durationpb.Duration, maximum time.Duration) bool {
	if v == nil || v.CheckValid() != nil {
		return false
	}
	d := v.AsDuration()
	if d <= 0 || d > maximum {
		return false
	}
	roundtrip := durationpb.New(d)
	return roundtrip.Seconds == v.Seconds && roundtrip.Nanos == v.Nanos
}
