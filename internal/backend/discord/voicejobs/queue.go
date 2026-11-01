package voicejobs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math"
	"sort"
	"time"

	rt "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
)

type continuation struct {
	Owner      rt.InstanceID
	Guild      string
	Generation uint64
	Offset     int
}
type queueEntry struct {
	snapshot *wire.PlaybackSnapshot
	ordinal  uint64
}

func stale() error {
	return failure(codes.FailedPrecondition, wire.VoiceErrorReason_VOICE_ERROR_REASON_STALE_CONTINUATION, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONTROL)
}
func (s *Service) queueSnapshot(owner rt.InstancePrincipal, guildID string) ([]queueEntry, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now())
	out := make([]queueEntry, 0)
	for _, ref := range s.jobs {
		if ref.owner == owner && ref.guild == guildID {
			view := ref.view
			if ref.final != nil {
				view = ref.final
			}
			out = append(out, queueEntry{view, ref.ordinal})
		}
	}
	return out, s.queries[guildID]
}
func queueRank(v *wire.PlaybackSnapshot) int {
	if terminal(v.State) {
		return 2
	}
	if v.State == wire.PlaybackState_PLAYBACK_STATE_PAUSED {
		return 1
	}
	return 0
}
func (s *Service) queuePage(owner rt.InstancePrincipal, r *wire.PlaybackQueueRequest, entries []queueEntry, generation uint64) (*wire.PlaybackQueue, error) {
	cursor := continuation{Owner: owner.InstanceID, Guild: r.GuildId, Generation: generation}
	if generation == math.MaxUint64 {
		return nil, stale()
	}
	if r.Continuation != "" {
		b, e := base64.RawURLEncoding.DecodeString(r.Continuation)
		if e != nil || json.Unmarshal(b, &cursor) != nil || cursor.Owner != owner.InstanceID || cursor.Guild != r.GuildId || cursor.Generation != generation || cursor.Offset < 0 {
			return nil, stale()
		}
	}
	for _, entry := range entries {
		if entry.snapshot == nil {
			return nil, stale()
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if queueRank(a.snapshot) != queueRank(b.snapshot) {
			return queueRank(a.snapshot) < queueRank(b.snapshot)
		}
		if a.snapshot.Priority != b.snapshot.Priority {
			return a.snapshot.Priority > b.snapshot.Priority
		}
		return a.ordinal < b.ordinal
	})
	if cursor.Offset > len(entries) {
		return nil, stale()
	}
	out := &wire.PlaybackQueue{}
	offset := cursor.Offset
	for offset < len(entries) && len(out.Jobs) < int(r.Limit) {
		previous := out.NextContinuation
		out.Jobs = append(out.Jobs, proto.Clone(entries[offset].snapshot).(*wire.PlaybackSnapshot))
		out.NextContinuation = ""
		if offset+1 < len(entries) {
			next := cursor
			next.Offset = offset + 1
			b, _ := json.Marshal(next)
			out.NextContinuation = base64.RawURLEncoding.EncodeToString(b)
		}
		if proto.Size(out) > s.config.MaxGRPCMessageBytes {
			out.Jobs = out.Jobs[:len(out.Jobs)-1]
			out.NextContinuation = previous
			if len(out.Jobs) == 0 {
				return nil, quota()
			}
			break
		}
		offset++
	}
	// A first page is the immutable snapshot captured before target
	// authorization. Later publications invalidate only continuation reads,
	// not the already captured and authorized first-page view.
	if r.Continuation != "" {
		s.mu.Lock()
		same := generation == s.queries[r.GuildId]
		s.mu.Unlock()
		if !same {
			return nil, stale()
		}
	}
	return out, nil
}
func (h *server) GetPlaybackQueue(ctx context.Context, r *wire.PlaybackQueueRequest) (*wire.PlaybackQueue, error) {
	p, done, err := h.begin(ctx, "GetPlaybackQueue")
	if err != nil {
		return nil, err
	}
	defer done()
	s := h.service
	if r == nil || !snowflake(r.GuildId) || r.Limit == 0 || uint64(r.Limit) > uint64(s.config.QueuePageSize) || len(r.Continuation) > s.config.MaxGRPCMessageBytes {
		return nil, invalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE)
	}
	entries, generation := s.queueSnapshot(p, r.GuildId)
	scopes := make([]*corewire.ResourceScope, 0)
	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.snapshot == nil {
			return nil, stale()
		}
		channel := entry.snapshot.ChannelId
		if !seen[channel] {
			seen[channel] = true
			scopes = append(scopes, &corewire.ResourceScope{SelectorKind: &corewire.ResourceScope_Selector{Selector: &corewire.ResourceSelector{ResourceIds: map[string]string{"guild_id": r.GuildId, "channel_id": channel}}}})
		}
	}
	if len(scopes) == 0 {
		scopes = append(scopes, &corewire.ResourceScope{SelectorKind: &corewire.ResourceScope_Selector{Selector: &corewire.ResourceSelector{ResourceIds: map[string]string{"guild_id": r.GuildId}}}})
	}
	if _, err = h.services.Authorizer.Authorize(ctx, rt.AccessRequest{Backend: "discord", Operation: "GetPlaybackQueue", Scopes: scopes}); err != nil {
		return nil, err
	}
	return s.queuePage(p, r, entries, generation)
}
