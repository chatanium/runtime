package voicejobs

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
	rt "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestOneProducerAndExplicitHalfClose(t *testing.T) {
	g, f, p := fixtureGuild(t)
	j := fixtureJob(t, g, p, "job", 1)
	j.bound = false
	if _, err := g.bind(j.id); err != nil {
		t.Fatal(err)
	}
	if _, err := g.bind(j.id); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("second producer accepted")
	}
	acceptFixture(t, g, j, 1)
	if err := g.accept(j, endInput(1)); err != nil {
		t.Fatal(err)
	}
	sent := handoffFixture(t, g, f, j)
	g.inputEOF(j.id)
	if j.stopping != nil || terminal(j.snapshot.State) {
		t.Fatal("normal EndInput half-close canceled or completed the handoff")
	}
	receiptFixture(t, g, sent, nil)
	g.schedule()
	if j.snapshot.State != wire.PlaybackState_PLAYBACK_STATE_COMPLETED {
		t.Fatal("terminal completion lost after half-close")
	}
}
func TestResumeDoesNotResetRunningOrCancelPendingPause(t *testing.T) {
	g, f, p := fixtureGuild(t)
	j := fixtureJob(t, g, p, "job", 1)
	acceptFixture(t, g, j, 1)
	sent := handoffFixture(t, g, f, j)
	before := snapshot(j)
	value, err := g.controlJob(j.id, "ResumePlaybackJob", nil)
	if err != nil || value.(*wire.PlaybackSnapshot).State != before.State || j.ordinal != g.service.jobs[j.id].ordinal {
		t.Fatal("running resume changed state or FIFO ordinal")
	}
	reply := make(chan answer, 1)
	if _, err = g.controlJob(j.id, "PausePlaybackJob", reply); err != errDeferred {
		t.Fatal("pause did not retain its boundary")
	}
	if _, err = g.controlJob(j.id, "ResumePlaybackJob", nil); err != nil {
		t.Fatal(err)
	}
	receiptFixture(t, g, sent, nil)
	if (<-reply).value.(*wire.PlaybackSnapshot).State != wire.PlaybackState_PLAYBACK_STATE_PAUSED {
		t.Fatal("overlapping resume stranded a pause reply")
	}
}
func TestFirstBindAndGrantedInputIdleDeadlines(t *testing.T) {
	g, _, p := fixtureGuild(t)
	j := fixtureJob(t, g, p, "bind", 1)
	j.bound = false
	j.firstBind = time.Unix(10, 0)
	g.expire(time.Unix(11, 0))
	if j.snapshot.TerminalError.Reason != wire.VoiceErrorReason_VOICE_ERROR_REASON_BIND_TIMEOUT {
		t.Fatal("unbound job escaped its deadline")
	}
	g, _, p = fixtureGuild(t)
	j = fixtureJob(t, g, p, "idle", 1)
	g.renew(j)
	if j.idleSince.IsZero() {
		t.Fatal("available credit did not start active producer deadline")
	}
	g.expire(j.idleSince.Add(2 * g.service.config.InputIdleTimeout))
	if j.snapshot.TerminalError.Reason != wire.VoiceErrorReason_VOICE_ERROR_REASON_INPUT_TIMEOUT {
		t.Fatal("active producer inactivity not failed")
	}
}
func TestLifetimeConversionCannotSaturateOrWrap(t *testing.T) {
	if validLifetime(&durationpb.Duration{Seconds: 315576000000}, time.Duration(math.MaxInt64)) {
		t.Fatal("oversized wire lifetime saturated into a valid Go duration")
	}
	if validLifetime(durationpb.New(0), time.Hour) || validLifetime(durationpb.New(-time.Second), time.Hour) || !validLifetime(durationpb.New(time.Second), time.Hour) {
		t.Fatal("finite lifetime validation incorrect")
	}
}
func TestUnusedCreditsParticipateInInstanceAndHostBudgets(t *testing.T) {
	g, _, p := fixtureGuild(t)
	g.service.config.InstanceFrames = 2
	g.service.config.HostFrames = 2
	first := fixtureJob(t, g, p, "first", 1)
	second := fixtureJob(t, g, p, "second", 1)
	if first.resFrames != 2 || second.snapshot.CreditThroughSequence != 0 || g.service.usage.frames != 2 {
		t.Fatal("unused credits were not reserved before producer input")
	}
	g.stopJob(first, stopped(), true)
	g.renew(second)
	if second.snapshot.CreditThroughSequence != 2 || g.service.usage.frames != 2 {
		t.Fatal("released reservations did not restore bounded credit")
	}
}
func TestAdmissionQuotaAndDrainDoNotAlterExistingWork(t *testing.T) {
	g, _, p := fixtureGuild(t)
	j := fixtureJob(t, g, p, "job", 1)
	expiry := j.snapshot.ExpiresAt.AsTime()
	g.service.config.InstanceJobs = 1
	if _, err := g.createJob(p, "excess", &wire.CreatePlaybackJobRequest{Lifetime: durationpb.New(time.Hour)}); status.Code(err) != codes.ResourceExhausted {
		t.Fatal("instance job quota ignored")
	}
	if err := g.service.Drain(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if _, err := g.createJob(p, "draining", &wire.CreatePlaybackJobRequest{Lifetime: durationpb.New(time.Hour)}); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("drain admitted new work")
	}
	if g.jobs[j.id] != j || !j.snapshot.ExpiresAt.AsTime().Equal(expiry) || terminal(j.snapshot.State) {
		t.Fatal("drain canceled or extended accepted work before parent deadline")
	}
}
func TestOptionalNativeAndIntentDenialAreNotWorkingFallbacks(t *testing.T) {
	g, _, p := fixtureGuild(t)
	s := g.service
	in := rt.BackendPreparation{Approved: &corewire.BackendGrant{BackendId: "discord", ProtocolMajor: 2, Capabilities: []*corewire.CapabilityGrant{{Name: ReceiveCapability}}}}
	binding, err := s.Prepare(context.Background(), p, in)
	if err != nil || len(binding.Grant.Capabilities) != 0 {
		t.Fatal("ordinary backend advertised native voice")
	}
	in.Requirement = &corewire.BackendRequirement{RequiredCapabilities: []*corewire.CapabilityRequest{{Name: ReceiveCapability}}}
	if _, err = s.Prepare(context.Background(), p, in); status.Code(err) != codes.Unavailable {
		t.Fatal("required native capability did not fail activation")
	}
	s.available = true
	s.intentsAvailable = false
	if _, err = s.Prepare(context.Background(), p, in); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("missing operator-approved voice intent was silently enabled")
	}
	in.Requirement = nil
	binding, err = s.Prepare(context.Background(), p, in)
	if err != nil || len(binding.Grant.Capabilities) != 0 {
		t.Fatal("optional missing intent was not declined")
	}
}
func TestTransportErrorsAreTypedAndSanitized(t *testing.T) {
	for _, test := range []struct {
		err    error
		code   codes.Code
		reason wire.VoiceErrorReason
	}{{discordgo.ErrVoiceUnavailable, codes.Unavailable, wire.VoiceErrorReason_VOICE_ERROR_REASON_VOICE_TRANSPORT_UNSUPPORTED}, {discordgo.ErrVoiceDAVETimeout, codes.DeadlineExceeded, wire.VoiceErrorReason_VOICE_ERROR_REASON_DAVE_NOT_READY}, {discordgo.ErrVoicePermissionDenied, codes.PermissionDenied, wire.VoiceErrorReason_VOICE_ERROR_REASON_DISCORD_PERMISSION_DENIED}, {discordgo.ErrVoiceChannelChanged, codes.Unavailable, wire.VoiceErrorReason_VOICE_ERROR_REASON_CHANNEL_CHANGED}, {errors.New("token=private voice key/path"), codes.Unavailable, wire.VoiceErrorReason_VOICE_ERROR_REASON_CONNECTION_LOST}} {
		e := transportFailure(test.err, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONNECTION)
		if status.Code(e) != test.code || e.detail.Reason != test.reason || strings.Contains(e.Error(), "private") || strings.Contains(e.detail.Message, "private") {
			t.Fatal("transport failure lost classification or leaked secrets")
		}
	}
}
