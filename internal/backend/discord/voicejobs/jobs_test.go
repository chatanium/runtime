package voicejobs

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
	rt "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// These are explicit fixture limits, not production defaults. No native library,
// credential, network socket, encoder, sleeps, or scheduler timing is needed.
func fixtureConfig() Config {
	return Config{
		Transport:    discordgo.VoiceConfig{MaxWebSocketBytes: 8192, MaxControlMessages: 8, MaxParticipants: 8, MaxDecryptors: 8, MaxProposalBytes: 2048, MaxProposals: 8, MaxTransitions: 8, MaxTransitionBytes: 4096, MaxOpusBytes: 256, MaxEncryptedFrameBytes: 512, MaxUDPPacketBytes: 1024, ReceiveQueuePackets: 8, ReceiveQueueBytes: 2048, HandshakeTimeout: time.Second, RekeyTimeout: time.Second, WriteTimeout: time.Second, UDPDiscoveryTimeout: time.Second, UDPKeepAliveInterval: time.Second, HeartbeatTimeout: time.Second, SubmitTimeout: time.Second, ReceiptTimeout: time.Second, CloseTimeout: time.Second},
		HostSessions: 8, InstanceSessions: 4, GuildJobs: 8, InstanceJobs: 8, HostJobs: 16, WaitingJobs: 16, JobFrames: 4, InstanceFrames: 16, HostFrames: 32, JobBytes: 1024, InstanceBytes: 4096, HostBytes: 8192, InitialCreditFrames: 2, MaxOpusPacketBytes: 256, MaxGRPCMessageBytes: 4096, InstanceMessageBytes: 32768, HostMessageBytes: 65536, JobLifetime: time.Hour, FirstBindTimeout: time.Minute, InputIdleTimeout: time.Minute, ConnectionTimeout: time.Second, SubmissionTimeout: time.Second, ReceiptTimeout: time.Second, CleanupTimeout: 5 * time.Second, InstanceSubscriptions: 4, GuildSubscriptions: 4, HostSubscriptions: 8, SubscriptionLifetime: time.Hour, SubscriptionPackets: 2, HostReceivePackets: 8, SubscriptionBytes: 512, HostReceiveBytes: 2048, SlowConsumerTimeout: time.Minute, MaxSSRCFilters: 4, StatusMailbox: 2, ControlMailbox: 32, StatusMailboxBytes: 12288, HostStatusBytes: 196608, TerminalRecords: 16, TerminalTTL: time.Minute, QueuePageSize: 8, RelationshipTimeout: time.Second,
	}
}

type fixtureSubmission struct {
	done chan discordgo.OpusWriteResult
}

func (f *fixtureSubmission) Done() <-chan discordgo.OpusWriteResult { return f.done }

type fixtureSend struct {
	opus    []byte
	receipt *fixtureSubmission
}
type fixtureTransport struct {
	sent          chan fixtureSend
	done, changed chan struct{}
	ready         bool
	once          sync.Once
	leaves        atomic.Int32
}

func newFixtureTransport() *fixtureTransport {
	return &fixtureTransport{sent: make(chan fixtureSend, 8), done: make(chan struct{}), changed: make(chan struct{}), ready: true}
}
func (f *fixtureTransport) SubmitOpus(ctx context.Context, p []byte) (Submission, error) {
	if !f.ready {
		return nil, discordgo.ErrVoiceNotReady
	}
	r := &fixtureSubmission{make(chan discordgo.OpusWriteResult, 1)}
	select {
	case f.sent <- fixtureSend{p, r}:
		return r, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (f *fixtureTransport) ReceiveOpus(ctx context.Context) (*discordgo.Packet, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.done:
		return nil, errors.New("fixture connection closed")
	}
}
func (f *fixtureTransport) ReadyState() bool                                  { return f.ready }
func (f *fixtureTransport) ReadinessChanged() <-chan struct{}                 { return f.changed }
func (f *fixtureTransport) Done() <-chan struct{}                             { return f.done }
func (f *fixtureTransport) Err() error                                        { return nil }
func (f *fixtureTransport) SetStateContext(context.Context, bool, bool) error { return nil }
func (f *fixtureTransport) CloseContext(context.Context) error {
	f.once.Do(func() { close(f.done) })
	return nil
}
func (f *fixtureTransport) DisconnectContext(ctx context.Context) error {
	f.leaves.Add(1)
	return f.CloseContext(ctx)
}

func fixtureGuild(t *testing.T) (*guild, *fixtureTransport, rt.InstancePrincipal) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := rt.InstancePrincipal{ModuleID: "module", InstanceID: "owner"}
	c := fixtureConfig()
	s := &Service{config: c, ctx: ctx, cancel: cancel, instances: map[rt.InstanceID]*instance{}, guilds: map[string]*guild{}, jobs: map[string]*jobRef{}, subs: map[string]*subRef{}, queries: map[string]uint64{}, changed: make(chan struct{})}
	s.instances[p.InstanceID] = &instance{services: rt.InstanceServices{Principal: p}, active: true, ctx: ctx, cancel: cancel}
	f := newFixtureTransport()
	g := &guild{service: s, id: "123", channel: "456", ctx: ctx, cancel: cancel, commands: make(chan command, c.ControlMailbox), done: make(chan struct{}), jobs: map[string]*job{}, subs: map[string]*subscription{}, owners: map[rt.InstanceID]int{}, transport: f, sent: make(chan sendResult, 1), closed: make(chan error, 1), aborted: make(chan error, 1), stateResult: make(chan error, 1), joined: make(chan joinResult, 1), received: make(chan *discordgo.Packet), receiveError: make(chan error, 1)}
	s.guilds[g.id] = g
	return g, f, p
}
func fixtureJob(t *testing.T, g *guild, p rt.InstancePrincipal, id string, priority int32) *job {
	t.Helper()
	_, err := g.createJob(p, id, &wire.CreatePlaybackJobRequest{Priority: priority, Lifetime: durationpb.New(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	j := g.jobs[id]
	j.bound = true
	return j
}
func opusInput(sequence uint64) *wire.PlaybackInput {
	return &wire.PlaybackInput{Part: &wire.PlaybackInput_Frame{Frame: &wire.OpusFrame{Sequence: sequence, Opus: []byte{0xf8, 0xff, 0xfe}}}}
}
func endInput(sequence uint64) *wire.PlaybackInput {
	return &wire.PlaybackInput{Part: &wire.PlaybackInput_EndInput{EndInput: &wire.PlaybackEnd{FinalSequence: sequence}}}
}
func acceptFixture(t *testing.T, g *guild, j *job, sequence uint64) {
	t.Helper()
	if err := g.accept(j, opusInput(sequence)); err != nil {
		t.Fatal(err)
	}
}
func scheduleFixture(t *testing.T, g *guild) {
	t.Helper()
	g.schedule()
	for g.stateBusy {
		if err := <-g.stateResult; err != nil {
			t.Fatal(err)
		}
		g.stateBusy = false
		g.schedule()
	}
}
func handoffFixture(t *testing.T, g *guild, f *fixtureTransport, j *job) fixtureSend {
	t.Helper()
	scheduleFixture(t, g)
	if g.inflight != j {
		t.Fatalf("selected %v, want %s", g.inflight, j.id)
	}
	result := <-g.sent
	if !result.handed {
		t.Fatalf("handoff failed: %v", result.err)
	}
	g.onSend(result)
	return <-f.sent
}
func receiptFixture(t *testing.T, g *guild, sent fixtureSend, err error) {
	t.Helper()
	sent.receipt.done <- discordgo.OpusWriteResult{Err: err}
	g.onSend(<-g.sent)
}

func TestPriorityPreemptionResumesUnsubmittedSequence(t *testing.T) {
	g, f, p := fixtureGuild(t)
	a := fixtureJob(t, g, p, "a", 1)
	acceptFixture(t, g, a, 1)
	acceptFixture(t, g, a, 2)
	first := handoffFixture(t, g, f, a)
	b := fixtureJob(t, g, p, "b", 9)
	acceptFixture(t, g, b, 1)
	if err := g.accept(b, endInput(1)); err != nil {
		t.Fatal(err)
	}
	g.schedule()
	if g.inflight != a {
		t.Fatal("preempted a non-retractable handoff")
	}
	receiptFixture(t, g, first, nil)
	high := handoffFixture(t, g, f, b)
	if a.snapshot.LastSubmittedSequence != 1 || a.snapshot.Reason != wire.PlaybackReason_PLAYBACK_REASON_PREEMPTED {
		t.Fatal("preemption lost cursor/reason")
	}
	receiptFixture(t, g, high, nil)
	g.schedule()
	if b.snapshot.State != wire.PlaybackState_PLAYBACK_STATE_COMPLETED {
		t.Fatal("explicit ended high priority job did not complete")
	}
	// schedule above immediately chooses A; consume that handoff without a second
	// call that could hide an unintended submission.
	r := <-g.sent
	g.onSend(r)
	next := <-f.sent
	if g.inflight != a || a.snapshot.LastSubmittedSequence != 2 {
		t.Fatal("resumed from the wrong sequence")
	}
	receiptFixture(t, g, next, nil)
}
func TestFIFOAndInputStarvation(t *testing.T) {
	g, f, p := fixtureGuild(t)
	a := fixtureJob(t, g, p, "a", 2)
	b := fixtureJob(t, g, p, "b", 2)
	c := fixtureJob(t, g, p, "c", 2)
	acceptFixture(t, g, b, 1)
	acceptFixture(t, g, c, 1)
	sent := handoffFixture(t, g, f, b)
	acceptFixture(t, g, a, 1)
	receiptFixture(t, g, sent, nil)
	sent = handoffFixture(t, g, f, a)
	receiptFixture(t, g, sent, nil)
	sent = handoffFixture(t, g, f, c)
	receiptFixture(t, g, sent, nil)
}
func TestPauseBoundaryKeepsCreditsAndFrames(t *testing.T) {
	g, f, p := fixtureGuild(t)
	j := fixtureJob(t, g, p, "a", 1)
	acceptFixture(t, g, j, 1)
	sent := handoffFixture(t, g, f, j)
	through, bytes := j.snapshot.CreditThroughSequence, j.snapshot.CreditThroughBytes
	waiter := make(chan answer, 1)
	if _, err := g.controlJob(j.id, "PausePlaybackJob", waiter); err != errDeferred {
		t.Fatal("pause did not defer to receipt")
	}
	acceptFixture(t, g, j, 2)
	g.schedule()
	select {
	case <-waiter:
		t.Fatal("pause acknowledged before receipt")
	default:
	}
	receiptFixture(t, g, sent, nil)
	ack := <-waiter
	if ack.value.(*wire.PlaybackSnapshot).State != wire.PlaybackState_PLAYBACK_STATE_PAUSED {
		t.Fatal("pause boundary not reflected")
	}
	g.schedule()
	if g.inflight != nil || j.snapshot.CreditThroughSequence != through || j.snapshot.CreditThroughBytes != bytes || j.frames.count != 1 {
		t.Fatal("paused job submitted, renewed or lost data")
	}
	if _, err := g.controlJob(j.id, "ResumePlaybackJob", nil); err != nil {
		t.Fatal(err)
	}
	sent = handoffFixture(t, g, f, j)
	if j.snapshot.LastSubmittedSequence != 2 {
		t.Fatal("resume reset cursor")
	}
	receiptFixture(t, g, sent, nil)
}
func TestCompletionRequiresExplicitEndAndReceipt(t *testing.T) {
	g, f, p := fixtureGuild(t)
	j := fixtureJob(t, g, p, "one", 1)
	acceptFixture(t, g, j, 1)
	if err := g.accept(j, endInput(1)); err != nil {
		t.Fatal(err)
	}
	sent := handoffFixture(t, g, f, j)
	if terminal(j.snapshot.State) {
		t.Fatal("completed before UDP receipt")
	}
	receiptFixture(t, g, sent, nil)
	g.schedule()
	if j.snapshot.State != wire.PlaybackState_PLAYBACK_STATE_COMPLETED {
		t.Fatal("final receipt did not complete")
	}
	g, _, p = fixtureGuild(t)
	empty := fixtureJob(t, g, p, "empty", 1)
	if err := g.accept(empty, endInput(0)); err != nil {
		t.Fatal(err)
	}
	if empty.snapshot.State != wire.PlaybackState_PLAYBACK_STATE_COMPLETED {
		t.Fatal("empty explicit input was not completed")
	}
	g, _, p = fixtureGuild(t)
	truncated := fixtureJob(t, g, p, "truncated", 1)
	g.inputEOF(truncated.id)
	if truncated.snapshot.State != wire.PlaybackState_PLAYBACK_STATE_FAILED || truncated.snapshot.TerminalError.Reason != wire.VoiceErrorReason_VOICE_ERROR_REASON_INPUT_TRUNCATED {
		t.Fatal("truncated EOF became successful")
	}
}
func TestCreditSequenceAndByteValidation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*job)
		input  *wire.PlaybackInput
		reason wire.VoiceErrorReason
	}{
		{"gap", func(*job) {}, opusInput(2), wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_SEQUENCE},
		{"duplicate", func(j *job) { j.snapshot.LastAcceptedSequence = 1 }, opusInput(1), wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_SEQUENCE},
		{"frame credit", func(j *job) { j.snapshot.CreditThroughSequence = 0 }, opusInput(1), wire.VoiceErrorReason_VOICE_ERROR_REASON_CREDIT_EXCEEDED},
		{"byte credit", func(j *job) { j.snapshot.CreditThroughBytes = 2 }, opusInput(1), wire.VoiceErrorReason_VOICE_ERROR_REASON_CREDIT_EXCEEDED},
		{"wrong final", func(*job) {}, endInput(1), wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_FINAL_SEQUENCE},
		{"after end", func(j *job) { j.snapshot.InputEnded = true }, opusInput(1), wire.VoiceErrorReason_VOICE_ERROR_REASON_INPUT_AFTER_END},
		{"wrap", func(j *job) { j.snapshot.LastAcceptedSequence = math.MaxUint64 }, opusInput(0), wire.VoiceErrorReason_VOICE_ERROR_REASON_SEQUENCE_EXHAUSTED},
		{"invalid opus", func(*job) {}, &wire.PlaybackInput{Part: &wire.PlaybackInput_Frame{Frame: &wire.OpusFrame{Sequence: 1, Opus: []byte{}}}}, wire.VoiceErrorReason_VOICE_ERROR_REASON_INVALID_OPUS},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g, _, p := fixtureGuild(t)
			j := fixtureJob(t, g, p, "job", 1)
			c.mutate(j)
			err := g.accept(j, c.input)
			v, ok := err.(*voiceFailure)
			if !ok || v.detail.Reason != c.reason {
				t.Fatalf("got %v want %v", err, c.reason)
			}
		})
	}
}
func TestAcceptanceTransfersOwnershipAndBoundsCredits(t *testing.T) {
	g, f, p := fixtureGuild(t)
	j := fixtureJob(t, g, p, "job", 1)
	input := opusInput(1)
	original := input.GetFrame().Opus
	if err := g.accept(j, input); err != nil {
		t.Fatal(err)
	}
	if input.GetFrame().Opus != nil {
		t.Fatal("decoded message retained transferred bytes")
	}
	sent := handoffFixture(t, g, f, j)
	if !reflect.DeepEqual(sent.opus, []byte{0xf8, 0xff, 0xfe}) || &sent.opus[0] != &original[0] {
		t.Fatal("handoff copied or changed the owned packet")
	}
	receiptFixture(t, g, sent, nil)
	for sequence := uint64(2); sequence < 100; sequence++ {
		g.renew(j)
		acceptFixture(t, g, j, sequence)
		sent = handoffFixture(t, g, f, j)
		receiptFixture(t, g, sent, nil)
		if j.resFrames > g.service.config.InitialCreditFrames || j.resBytes > int64(g.service.config.InitialCreditFrames*g.service.config.MaxOpusPacketBytes) {
			t.Fatal("cumulative unused byte credit grew without bound")
		}
	}
	g.stopJob(j, stopped(), true)
	if g.service.usage.frames != 0 || g.service.usage.bytes != 0 {
		t.Fatal("credits leaked on terminal cleanup")
	}
}
func TestAbsoluteLifetimeAndInputCreditDeadline(t *testing.T) {
	g, _, p := fixtureGuild(t)
	j := fixtureJob(t, g, p, "paused", 1)
	j.paused = true
	j.idleSince = time.Time{}
	j.snapshot.ExpiresAt = timestamppb.New(time.Unix(100, 0))
	g.expire(time.Unix(101, 0))
	if j.snapshot.TerminalError.GetReason() != wire.VoiceErrorReason_VOICE_ERROR_REASON_LIFETIME_EXCEEDED {
		t.Fatal("pause escaped absolute expiry")
	}
	g, _, p = fixtureGuild(t)
	j = fixtureJob(t, g, p, "no-credit", 1)
	acceptFixture(t, g, j, 1)
	acceptFixture(t, g, j, 2)
	j.idleSince = time.Time{}
	g.renew(j)
	if !j.idleSince.IsZero() {
		t.Fatal("no-credit waiting charged as producer inactivity")
	}
}
func TestTerminalRetentionAndOwnerIsolation(t *testing.T) {
	g, _, p := fixtureGuild(t)
	g.service.config.TerminalRecords = 2
	jobs := make([]*job, 0, 3)
	for n := range 3 {
		jobs = append(jobs, fixtureJob(t, g, p, fmt.Sprint(n), 1))
	}
	for _, j := range jobs {
		g.stopJob(j, stopped(), true)
	}
	if len(g.service.jobs) != 2 {
		t.Fatal("terminal record count unbounded")
	}
	g.service.pruneLocked(time.Now().Add(2 * g.service.config.TerminalTTL))
	if len(g.service.jobs) != 0 {
		t.Fatal("expired records retained")
	}
	g, _, p = fixtureGuild(t)
	j := fixtureJob(t, g, p, "owned", 1)
	h := &server{service: g.service}
	_, err := h.job(context.Background(), rt.InstancePrincipal{ModuleID: "other", InstanceID: "other"}, j.id, "CancelPlaybackJob")
	if status.Code(err) != codes.NotFound {
		t.Fatal("foreign owner learned a resource")
	}
}
func TestMetadataCannotCreateVoiceAuthority(t *testing.T) {
	h := &server{}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("module-id", "forged", "instance-id", "forged"))
	_, err := h.CreatePlaybackJob(ctx, &wire.CreatePlaybackJobRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("metadata bypassed principal: %v", err)
	}
}
func TestPriorityConstraintMustBeTypedAndNarrowed(t *testing.T) {
	s := &Service{}
	if s.ValidateConstraints(&corewire.CapabilityGrant{Name: PlayCapability}) == nil {
		t.Fatal("missing constraint became unlimited")
	}
	a, _ := anypb.New(&wire.VoicePlaybackConstraints{MaxPriority: 1})
	b, _ := anypb.New(&wire.VoicePlaybackConstraints{MaxPriority: 3})
	low := &corewire.CapabilityGrant{Name: PlayCapability, Constraints: a}
	high := &corewire.CapabilityGrant{Name: PlayCapability, Constraints: b}
	if s.ValidateConstraintsSubset(low, high) != nil || s.ValidateConstraintsSubset(high, low) == nil {
		t.Fatal("priority subset enforcement incorrect")
	}
}
func TestEveryResourceBoundIsRequired(t *testing.T) {
	base := fixtureConfig()
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	v := reflect.ValueOf(base)
	for n := range v.NumField() {
		if v.Type().Field(n).Name == "Transport" {
			continue
		}
		t.Run(v.Type().Field(n).Name, func(t *testing.T) {
			copy := base
			reflect.ValueOf(&copy).Elem().Field(n).SetInt(0)
			if copy.Validate() == nil {
				t.Fatal("missing resource bound accepted")
			}
		})
	}
}
func TestCancellationReceiptRaceReleasesOnce(t *testing.T) {
	g, f, p := fixtureGuild(t)
	j := fixtureJob(t, g, p, "job", 1)
	acceptFixture(t, g, j, 1)
	sent := handoffFixture(t, g, f, j)
	g.stopJob(j, stopped(), true)
	g.stopJob(j, stopped(), true)
	if g.service.usage.jobs != 1 {
		t.Fatal("reservation released before receipt")
	}
	receiptFixture(t, g, sent, nil)
	g.stopJob(j, stopped(), true)
	g.finishJob(j)
	if g.service.usage.jobs != 0 || g.service.usage.frames != 0 || g.service.usage.bytes != 0 || len(g.owners) != 0 {
		t.Fatal("duplicate cancellation/receipt cleanup changed accounting")
	}
	if j.snapshot.LastSubmittedSequence != 1 || j.snapshot.LastUdpWrittenSequence != 1 || j.snapshot.State != wire.PlaybackState_PLAYBACK_STATE_CANCELLED {
		t.Fatal("cancel rewound receipt cursor")
	}
}
func TestOperationClassesSeparateReceiveAndCleanup(t *testing.T) {
	s := &Service{}
	ops := s.Operations()
	if len(ops) != 8 {
		t.Fatal("missing RPC policy")
	}
	for _, p := range ops {
		if p.Operation == "SubscribeVoice" && (p.Capability != ReceiveCapability || p.Class != rt.LongLivedOperation) {
			t.Fatal("receive permission coupled to playback")
		}
		if p.Operation == "CancelPlaybackJob" || p.Operation == "UnsubscribeVoice" {
			if p.Class != rt.OwnerCleanupOperation {
				t.Fatal("cleanup disallowed during drain")
			}
		}
	}
}
