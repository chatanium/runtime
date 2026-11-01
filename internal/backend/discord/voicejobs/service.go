package voicejobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
	rt "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const PlayCapability = "discord.voice.play"
const ReceiveCapability = "discord.voice.receive"

type Options struct {
	Config  Config
	Session *discordgo.Session
	// ResolveChannel must use the parent's bounded trusted resource lookup, never
	// an asserted request guild. AwaitOperation has already succeeded when called.
	ResolveChannel func(context.Context, rt.InstancePrincipal, string) (string, error)
	// Factory is an explicit host integration/test seam. Nil uses the real SDK.
	Factory Factory
}
type usage struct {
	frames               int
	bytes                int64
	messages             int64
	jobs, subs, sessions int
}
type instance struct {
	services                   rt.InstanceServices
	prepared, active, draining bool
	ctx                        context.Context
	cancel                     context.CancelFunc
	usage                      usage
}
type jobRef struct {
	owner          rt.InstancePrincipal
	guild, channel string
	actor          *guild
	ordinal        uint64
	view           *wire.PlaybackSnapshot
	final          *wire.PlaybackSnapshot
	at             time.Time
}
type subRef struct {
	owner          rt.InstancePrincipal
	guild, channel string
	actor          *guild
	final          *wire.VoiceSubscriptionSnapshot
	at             time.Time
}
type Service struct {
	config              Config
	resolve             func(context.Context, rt.InstancePrincipal, string) (string, error)
	factory             Factory
	available           bool
	intentsAvailable    bool
	ctx                 context.Context
	cancel              context.CancelFunc
	mu                  sync.Mutex
	instances           map[rt.InstanceID]*instance
	guilds              map[string]*guild
	jobs                map[string]*jobRef
	subs                map[string]*subRef
	queries             map[string]uint64
	usage               usage
	statusBytes         int64
	receivePackets      int
	receiveBytes        int64
	ordinal, generation uint64
	closed              bool
	done                chan struct{}
	changed             chan struct{}
	recordsChanged      chan struct{}
	cleanupErr          error
}

func New(ctx context.Context, o Options) (*Service, error) {
	if err := o.Config.Validate(); err != nil {
		return nil, err
	}
	if o.ResolveChannel == nil {
		return nil, fmt.Errorf("voicejobs: trusted channel resolver required")
	}
	available := discordgo.VoiceAvailable()
	f := o.Factory
	if f == nil {
		if o.Session == nil {
			return nil, fmt.Errorf("voicejobs: host session required")
		}
		f = sdkFactory(o.Session, o.Config.Transport)
	} else {
		available = true
	}
	intentsAvailable := true
	if o.Factory == nil {
		o.Session.RLock()
		intentsAvailable = o.Session.Identify.Intents&discordgo.IntentGuildVoiceStates != 0
		o.Session.RUnlock()
	}
	life, cancel := context.WithCancel(ctx)
	s := &Service{config: o.Config, resolve: o.ResolveChannel, factory: f, available: available, ctx: life, cancel: cancel, instances: map[rt.InstanceID]*instance{}, guilds: map[string]*guild{}, jobs: map[string]*jobRef{}, subs: map[string]*subRef{}, done: make(chan struct{}), changed: make(chan struct{})}
	s.queries = make(map[string]uint64)
	s.recordsChanged = make(chan struct{}, 1)
	s.intentsAvailable = intentsAvailable
	go s.reaper()
	return s, nil
}
func (s *Service) Operations() []rt.OperationPolicy {
	names := []string{"CreatePlaybackJob", "StreamPlayback", "PausePlaybackJob", "ResumePlaybackJob", "CancelPlaybackJob", "GetPlaybackQueue", "SubscribeVoice", "UnsubscribeVoice"}
	out := make([]rt.OperationPolicy, 0, len(names))
	for _, n := range names {
		cap := PlayCapability
		if n == "SubscribeVoice" || n == "UnsubscribeVoice" {
			cap = ReceiveCapability
		}
		class := rt.FiniteOperation
		if n == "CreatePlaybackJob" || n == "StreamPlayback" || n == "SubscribeVoice" {
			class = rt.LongLivedOperation
		}
		if n == "CancelPlaybackJob" || n == "UnsubscribeVoice" {
			class = rt.OwnerCleanupOperation
		}
		// Finite controls/queries still require an exact live event work
		// reference in drain. Owned cleanup is eligible by class alone.
		out = append(out, rt.OperationPolicy{Backend: "discord", Operation: n, Capability: cap, Class: class, DrainSafe: class == rt.FiniteOperation})
	}
	return out
}
func (s *Service) Register(v rt.InstanceServices) (core.HelperRegistrar, error) {
	if v.Limits.ControlMessageMaxBytes != s.config.MaxGRPCMessageBytes {
		return nil, fmt.Errorf("voicejobs: gRPC bound must match the instance transport limit")
	}
	if v.Authorizer == nil {
		return nil, fmt.Errorf("voicejobs: instance authorizer required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, stopped()
	}
	if s.instances[v.Principal.InstanceID] != nil {
		return nil, fmt.Errorf("voicejobs: duplicate instance")
	}
	ctx, cancel := context.WithCancel(s.ctx)
	s.instances[v.Principal.InstanceID] = &instance{services: v, ctx: ctx, cancel: cancel}
	return func(r grpc.ServiceRegistrar) error {
		wire.RegisterVoiceServiceServer(r, &server{service: s, services: v})
		return nil
	}, nil
}
func (s *Service) ValidateConstraints(g *corewire.CapabilityGrant) error {
	if g == nil {
		return invalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE)
	}
	if g.Name == PlayCapability {
		v := new(wire.VoicePlaybackConstraints)
		if g.Constraints == nil || g.Constraints.UnmarshalTo(v) != nil {
			return failure(codes.PermissionDenied, wire.VoiceErrorReason_VOICE_ERROR_REASON_PERMISSION_DENIED, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_ADMISSION)
		}
	}
	if g.Name == ReceiveCapability && g.Constraints != nil {
		return invalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE)
	}
	return nil
}
func (s *Service) ValidateConstraintsSubset(a, b *corewire.CapabilityGrant) error {
	if err := s.ValidateConstraints(a); err != nil {
		return err
	}
	if err := s.ValidateConstraints(b); err != nil {
		return err
	}
	if a.Name != b.Name {
		return invalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE)
	}
	if a.Name == PlayCapability {
		x, y := new(wire.VoicePlaybackConstraints), new(wire.VoicePlaybackConstraints)
		_ = a.Constraints.UnmarshalTo(x)
		_ = b.Constraints.UnmarshalTo(y)
		if x.MaxPriority > y.MaxPriority {
			return failure(codes.PermissionDenied, wire.VoiceErrorReason_VOICE_ERROR_REASON_PERMISSION_DENIED, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_ADMISSION)
		}
	}
	return nil
}
func (s *Service) Prepare(ctx context.Context, p rt.InstancePrincipal, in rt.BackendPreparation) (*rt.BackendBinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := &corewire.BackendGrant{BackendId: "discord", ProtocolMajor: 2}
	if in.Approved == nil || in.Approved.BackendId != "discord" || in.Approved.ProtocolMajor != 2 {
		return nil, admissionInvalid(wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE)
	}
	required := map[string]bool{}
	if in.Requirement != nil {
		for _, v := range in.Requirement.RequiredCapabilities {
			if v != nil {
				required[v.Name] = true
			}
		}
	}
	for _, g := range in.Approved.Capabilities {
		if g == nil || g.Name != PlayCapability && g.Name != ReceiveCapability {
			continue
		}
		if err := s.ValidateConstraints(g); err != nil {
			return nil, err
		}
		if !s.available {
			if required[g.Name] {
				return nil, failure(codes.Unavailable, wire.VoiceErrorReason_VOICE_ERROR_REASON_VOICE_TRANSPORT_UNSUPPORTED, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_ADMISSION)
			}
			continue
		}
		if !s.intentsAvailable {
			if required[g.Name] {
				return nil, status.Error(codes.FailedPrecondition, "BACKEND_RECONFIGURATION_REQUIRED")
			}
			continue
		}
		out.Capabilities = append(out.Capabilities, proto.Clone(g).(*corewire.CapabilityGrant))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.instances[p.InstanceID]
	if i == nil || i.services.Principal != p || i.ctx.Err() != nil {
		return nil, notFound()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	i.prepared = true
	return &rt.BackendBinding{Grant: out}, nil
}
func (s *Service) Activate(ctx context.Context, p rt.InstancePrincipal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.instances[p.InstanceID]
	if i == nil || i.services.Principal != p {
		return notFound()
	}
	if !i.prepared || i.draining || i.ctx.Err() != nil {
		return failure(codes.FailedPrecondition, wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_STATE, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_ADMISSION)
	}
	i.active = true
	return nil
}
func (s *Service) Drain(ctx context.Context, p rt.InstancePrincipal) error {
	s.mu.Lock()
	if i := s.instances[p.InstanceID]; i != nil && i.services.Principal == p {
		i.draining = true
	}
	s.mu.Unlock()
	return nil
}
func (s *Service) Cleanup(ctx context.Context, p rt.InstancePrincipal) error {
	bounded, cancel := context.WithTimeout(ctx, s.config.CleanupTimeout)
	defer cancel()
	ctx = bounded
	s.mu.Lock()
	i := s.instances[p.InstanceID]
	if i == nil || i.services.Principal != p {
		s.mu.Unlock()
		return nil
	}
	i.active = false
	i.draining = true
	i.cancel()
	affected := map[*guild]bool{}
	for _, r := range s.jobs {
		if r.owner == p && r.actor != nil {
			affected[r.actor] = true
		}
	}
	for _, r := range s.subs {
		if r.owner == p && r.actor != nil {
			affected[r.actor] = true
		}
	}
	for _, g := range s.guilds {
		if g.closingOwner == p.InstanceID {
			affected[g] = true
		}
	}
	actors := make([]*guild, 0, len(affected))
	for g := range affected {
		actors = append(actors, g)
	}
	s.mu.Unlock()
	for _, g := range actors {
		if err := g.call(ctx, func(g *guild) (any, error) { g.cleanupOwner(p); return nil, nil }); err != nil {
			select {
			case <-g.done:
				continue
			default:
				return err
			}
		}
	}
	for {
		s.mu.Lock()
		empty := i.usage.jobs == 0 && i.usage.subs == 0
		sessions := i.usage.sessions
		messages := i.usage.messages
		changed := s.changed
		s.mu.Unlock()
		if empty && messages == 0 && sessions == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return timeout(wire.VoiceErrorReason_VOICE_ERROR_REASON_CLEANUP_TIMEOUT, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CLEANUP)
		case <-changed:
		}
	}
	var cleanupErr error
	for _, g := range actors {
		select {
		case <-g.done:
			if g.cleanupErr != nil {
				cleanupErr = g.cleanupErr
			}
			continue
		default:
		}
		value, err := g.ask(ctx, func(g *guild) (any, error) { return len(g.owners) == 0, nil })
		if err != nil {
			select {
			case <-g.done:
				if g.cleanupErr != nil {
					cleanupErr = g.cleanupErr
				}
				continue
			default:
				return err
			}
		}
		if value.(bool) {
			select {
			case <-g.done:
				if g.cleanupErr != nil {
					cleanupErr = g.cleanupErr
				}
			case <-ctx.Done():
				return timeout(wire.VoiceErrorReason_VOICE_ERROR_REASON_CLEANUP_TIMEOUT, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CLEANUP)
			}
		}
	}
	s.mu.Lock()
	delete(s.instances, p.InstanceID)
	s.mu.Unlock()
	return cleanupErr
}
func (s *Service) Close(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, s.config.CleanupTimeout)
	defer cancel()
	ctx = bounded
	s.mu.Lock()
	s.closed = true
	s.cancel()
	actors := make([]*guild, 0, len(s.guilds))
	for _, g := range s.guilds {
		actors = append(actors, g)
	}
	for _, i := range s.instances {
		i.cancel()
	}
	s.mu.Unlock()
	for _, g := range actors {
		select {
		case <-g.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	select {
	case <-s.done:
		s.mu.Lock()
		err := s.cleanupErr
		s.mu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Service) reaper() {
	defer close(s.done)
	timer := time.NewTimer(s.config.TerminalTTL)
	defer timer.Stop()
	for {
		s.mu.Lock()
		s.pruneLocked(time.Now())
		var deadline time.Time
		for _, r := range s.jobs {
			if r.final != nil {
				deadline = earlier(deadline, r.at.Add(s.config.TerminalTTL))
			}
		}
		for _, r := range s.subs {
			if r.final != nil {
				deadline = earlier(deadline, r.at.Add(s.config.TerminalTTL))
			}
		}
		s.mu.Unlock()
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		var tick <-chan time.Time
		if !deadline.IsZero() {
			delay := time.Until(deadline)
			if delay < 0 {
				delay = 0
			}
			timer.Reset(delay)
			tick = timer.C
		}
		select {
		case <-s.recordsChanged:
		case <-tick:
		case <-s.ctx.Done():
			return
		}
	}
}
func (s *Service) pruneLocked(now time.Time) {
	type record struct {
		id, guild string
		at        time.Time
		job       bool
	}
	records := []record{}
	for id, r := range s.jobs {
		if r.final != nil {
			if now.Sub(r.at) >= s.config.TerminalTTL {
				delete(s.jobs, id)
				s.bumpLocked(r.guild)
			} else {
				records = append(records, record{id, r.guild, r.at, true})
			}
		}
	}
	for id, r := range s.subs {
		if r.final != nil {
			if now.Sub(r.at) >= s.config.TerminalTTL {
				delete(s.subs, id)
			} else {
				records = append(records, record{id, "", r.at, false})
			}
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].at.Before(records[j].at) })
	for len(records) > s.config.TerminalRecords {
		r := records[0]
		records = records[1:]
		if r.job {
			delete(s.jobs, r.id)
			s.bumpLocked(r.guild)
		} else {
			delete(s.subs, r.id)
		}
	}
	live := make(map[string]bool, len(s.guilds))
	for id := range s.guilds {
		live[id] = true
	}
	for _, r := range s.jobs {
		live[r.guild] = true
	}
	for id := range s.queries {
		if !live[id] {
			delete(s.queries, id)
		}
	}
}
func opaque() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", failure(codes.Internal, wire.VoiceErrorReason_VOICE_ERROR_REASON_INTERNAL, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_ADMISSION)
	}
	return hex.EncodeToString(b[:]), nil
}
func (s *Service) reserveFrames(j *job, frames int, bytes int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.instances[j.owner.InstanceID]
	if i == nil {
		return false
	}
	if frames < 0 || bytes < 0 || frames > s.config.JobFrames-j.resFrames || bytes > s.config.JobBytes-j.resBytes || frames > s.config.InstanceFrames-i.usage.frames || bytes > s.config.InstanceBytes-i.usage.bytes || frames > s.config.HostFrames-s.usage.frames || bytes > s.config.HostBytes-s.usage.bytes {
		return false
	}
	j.resFrames += frames
	j.resBytes += bytes
	i.usage.frames += frames
	i.usage.bytes += bytes
	s.usage.frames += frames
	s.usage.bytes += bytes
	return true
}
func (s *Service) releaseFrames(j *job, frames int, bytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j.resFrames -= frames
	j.resBytes -= bytes
	s.usage.frames -= frames
	s.usage.bytes -= bytes
	if i := s.instances[j.owner.InstanceID]; i != nil {
		i.usage.frames -= frames
		i.usage.bytes -= bytes
	}
	s.signalLocked()
}
func (s *Service) signalLocked() { close(s.changed); s.changed = make(chan struct{}) }
func (s *Service) bumpLocked(guildID string) {
	if s.generation < math.MaxUint64 {
		s.generation++
	}
	s.queries[guildID] = s.generation
	s.signalLocked()
}
func (s *Service) instanceLifetime(p rt.InstancePrincipal) (context.Context, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.instances[p.InstanceID]
	if i == nil || i.services.Principal != p {
		return nil, stopped()
	}
	return i.ctx, nil
}
func (s *Service) retainedJob(p rt.InstancePrincipal, id string) *wire.PlaybackSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.jobs[id]
	if r != nil && r.owner == p && r.final != nil {
		return proto.Clone(r.final).(*wire.PlaybackSnapshot)
	}
	return nil
}
func (s *Service) retainedSub(p rt.InstancePrincipal, id string) *wire.VoiceSubscriptionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.subs[id]
	if r != nil && r.owner == p && r.final != nil {
		return proto.Clone(r.final).(*wire.VoiceSubscriptionSnapshot)
	}
	return nil
}
func (s *Service) notifyRecordsLocked() {
	select {
	case s.recordsChanged <- struct{}{}:
	default:
	}
}
