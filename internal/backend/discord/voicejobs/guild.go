package voicejobs

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
	rt "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type answer struct {
	value any
	err   error
}
type command struct {
	ctx   context.Context
	run   func(*guild) (any, error)
	reply chan answer
}
type frame struct {
	sequence uint64
	opus     []byte
}
type job struct {
	id              string
	owner           rt.InstancePrincipal
	ordinal         uint64
	snapshot        *wire.PlaybackSnapshot
	frames          frameQueue
	acceptedBytes   uint64
	resFrames       int
	resBytes        int64
	bound           bool
	firstBind       time.Time
	idleSince       time.Time
	status          chan *wire.PlaybackSnapshot
	statusRelease   sync.Once
	terminalDone    chan struct{}
	streamEnded     bool
	paused, pausing bool
	stopping        *voiceFailure
	cancelState     bool
	waiters         []chan answer
}
type subscription struct {
	id             string
	owner          rt.InstancePrincipal
	snapshot       *wire.VoiceSubscriptionSnapshot
	filters        map[uint32]struct{}
	events         chan *wire.VoiceReceiveEvent
	header         *wire.VoiceReceiveEvent
	released       chan struct{}
	deliveryActive bool
	packets        int
	bytes          int64
	pendingSince   time.Time
	waiters        []chan answer
	terminal       bool
}
type sendResult struct {
	j      *job
	handed bool
	err    error
	bytes  int
}
type joinResult struct {
	transport Transport
	err       error
}
type guild struct {
	service                                   *Service
	id, channel                               string
	generation                                uint64
	ctx                                       context.Context
	cancel                                    context.CancelFunc
	commands                                  chan command
	done                                      chan struct{}
	jobs                                      map[string]*job
	subs                                      map[string]*subscription
	owners                                    map[rt.InstanceID]int
	initialized, joining, closing, shutting   bool
	retiring                                  bool
	joinCancel                                context.CancelFunc
	transport                                 Transport
	joined                                    chan joinResult
	sent                                      chan sendResult
	received                                  chan *discordgo.Packet
	receiveError                              chan error
	stateResult                               chan error
	closed                                    chan error
	inflight                                  *job
	inflightFrame                             frame
	handed                                    bool
	stateBusy                                 bool
	muted, deaf                               bool
	closeStarted                              bool
	aborted                                   chan error
	aborting, abortWaiting, disconnectWaiting bool
	abortFailure                              *voiceFailure
	cleanupErr                                error
	forceClose                                bool
	receiveSequence                           uint64
	// Protected by service.mu, including reads during instance cleanup.
	closingOwner rt.InstanceID
	admissions   int
}

// actor pins its result until the caller releases the admission after ask.
// This prevents retirement between lookup and owner-lane admission.
func (s *Service) actor(guildID, channelID string) (*guild, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return nil, stopped()
	}
	if g := s.guilds[guildID]; g != nil {
		if g.channel != channelID {
			return nil, failure(codes.FailedPrecondition, wire.VoiceErrorReason_VOICE_ERROR_REASON_CHANNEL_CONFLICT, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_ADMISSION)
		}
		g.admissions++
		return g, nil
	}
	if len(s.guilds) >= s.config.HostSessions || s.generation == math.MaxUint64 {
		return nil, quota()
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(s.ctx))
	s.generation++
	g := &guild{
		service: s, id: guildID, channel: channelID, generation: s.generation, ctx: ctx, cancel: cancel, admissions: 1,
		commands: make(chan command, s.config.ControlMailbox), done: make(chan struct{}),
		jobs: map[string]*job{}, subs: map[string]*subscription{}, owners: map[rt.InstanceID]int{},
		joined: make(chan joinResult, 1), sent: make(chan sendResult, 1),
		stateResult: make(chan error, 1), closed: make(chan error, 1), aborted: make(chan error, 1),
	}
	s.guilds[guildID] = g
	go g.run()
	return g, nil
}
func (g *guild) releaseAdmission() {
	g.service.mu.Lock()
	g.admissions--
	g.service.signalLocked()
	g.service.mu.Unlock()
}
func (g *guild) ask(ctx context.Context, f func(*guild) (any, error)) (any, error) {
	return g.execute(ctx, command{ctx: ctx, run: f, reply: make(chan answer, 1)})
}
func (g *guild) execute(ctx context.Context, c command) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-g.done:
		return nil, notFound()
	default:
	}
	select {
	case g.commands <- c:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-g.done:
		return nil, notFound()
	}
	select {
	case x := <-c.reply:
		return x.value, x.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-g.done:
		select {
		case x := <-c.reply:
			return x.value, x.err
		default:
			return nil, notFound()
		}
	}
}
func (g *guild) call(ctx context.Context, f func(*guild) (any, error)) error {
	_, err := g.ask(ctx, f)
	return err
}
func (g *guild) post(f func(*guild) (any, error)) {
	select {
	case g.commands <- command{ctx: g.ctx, run: f, reply: make(chan answer, 1)}:
	case <-g.done:
	}
}
func (g *guild) run() {
	defer close(g.done)
	defer g.cancel()
	shutdown := g.service.ctx.Done()
	admissionDeadline := time.Now().Add(g.service.config.FirstBindTimeout)
	timer := time.NewTimer(g.service.config.FirstBindTimeout)
	defer timer.Stop()
	for {
		if !g.initialized && !time.Now().Before(admissionDeadline) {
			g.initialized = true
		}
		changed := g.service.changedSignal()
		g.expire(time.Now())
		g.schedule()
		if g.closeStarted && g.transport == nil && !g.joining && len(g.jobs) == 0 && len(g.subs) == 0 && g.inflight == nil {
			if g.remove() {
				return
			}
		}
		deadline := g.deadline()
		if !g.initialized {
			deadline = earlier(deadline, admissionDeadline)
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		var tick <-chan time.Time
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d < 0 {
				d = 0
			}
			timer.Reset(d)
			tick = timer.C
		}
		var ready, failed <-chan struct{}
		if g.transport != nil && !g.closeStarted && !g.closing {
			ready = g.transport.ReadinessChanged()
			failed = g.transport.Done()
		}
		var cleanupReady <-chan struct{}
		if g.transport != nil && (g.abortWaiting || g.disconnectWaiting) {
			cleanupReady = g.transport.Done()
		}
		select {
		case c := <-g.commands:
			g.initialized = true
			if c.ctx.Err() != nil {
				c.reply <- answer{err: c.ctx.Err()}
				continue
			}
			v, e := c.run(g)
			if e != errDeferred {
				c.reply <- answer{v, e}
			}
		case r := <-g.joined:
			g.joining = false
			if g.joinCancel != nil {
				g.joinCancel()
				g.joinCancel = nil
			}
			if r.err != nil {
				g.failAll(transportFailure(r.err, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONNECTION))
			} else {
				g.transport = r.transport
				if g.closing {
					g.startClose()
				} else {
					g.received = make(chan *discordgo.Packet)
					g.receiveError = make(chan error, 1)
					go g.receive(r.transport, g.received, g.receiveError)
					g.activateReceivers()
				}
			}
		case r := <-g.sent:
			g.onSend(r)
		case p := <-g.received:
			g.fanout(p)
		case err := <-g.receiveError:
			if !g.closing {
				g.failAll(transportFailure(err, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_RECEIVE))
			}
		case err := <-g.stateResult:
			g.stateBusy = false
			if err != nil {
				g.failAll(transportFailure(err, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONTROL))
			}
		case <-ready:
			if err := g.transport.Err(); err != nil {
				g.failAll(transportFailure(err, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONNECTION))
			} else if !g.transport.ReadyState() {
				for _, j := range g.jobs {
					j.idleSince = time.Time{}
				}
			} else {
				g.activateReceivers()
			}
		case <-failed:
			g.failAll(transportFailure(g.transport.Err(), wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CONNECTION))
		case <-tick:
		case <-changed:
		case <-shutdown:
			g.shutting = true
			shutdown = nil
			g.failAll(stopped())
		case err := <-g.aborted:
			g.onAbort(err)
		case <-cleanupReady:
			g.cleanupJoined()
		case closeErr := <-g.closed:
			g.onDisconnect(closeErr)
		}
	}
}

// Only the actor may enter connection closing; the reservation remains indexed
// until the join and bounded disconnect workers have returned.
func (g *guild) schedule() {
	if g.initialized && len(g.jobs) == 0 && len(g.subs) == 0 && g.inflight == nil {
		if !g.closing {
			g.retiring = true
		}
		g.closing = true
		if g.joining && g.joinCancel != nil {
			g.joinCancel()
		}
		if !g.joining {
			g.startClose()
		}
		return
	}
	if g.closing {
		if !g.joining {
			if g.forceClose && g.inflight != nil {
				g.startAbort()
			} else if g.inflight == nil {
				g.startClose()
			}
		}
		return
	}
	if !g.joining && g.transport == nil && g.initialized {
		g.joining = true
		ctx, cancel := context.WithTimeout(g.ctx, g.service.config.ConnectionTimeout)
		g.joinCancel = cancel
		g.muted = len(g.jobs) == 0
		g.deaf = len(g.subs) == 0
		mute, deaf := g.muted, g.deaf
		go func() { v, e := g.service.factory(ctx, g.id, g.channel, mute, deaf); g.joined <- joinResult{v, e} }()
	}
	if g.transport == nil {
		return
	}
	mute, deaf := len(g.jobs) == 0, len(g.subs) == 0
	if !g.stateBusy && (mute != g.muted || deaf != g.deaf) {
		g.stateBusy = true
		g.muted, g.deaf = mute, deaf
		go func() {
			ctx, cancel := context.WithTimeout(g.ctx, g.service.config.SubmissionTimeout)
			defer cancel()
			g.stateResult <- g.transport.SetStateContext(ctx, mute, deaf)
		}()
	}
	if g.inflight != nil || g.stateBusy {
		return
	}
	var best *job
	var waiting *job
	for _, j := range g.jobs {
		if j.stopping != nil {
			g.finishJob(j)
			continue
		}
		if j.pausing {
			j.paused = true
			j.pausing = false
			g.setState(j, wire.PlaybackState_PLAYBACK_STATE_PAUSED, wire.PlaybackReason_PLAYBACK_REASON_OWNER_PAUSED)
			g.notifyWaiters(j)
		}
		if j.paused {
			j.idleSince = time.Time{}
			continue
		}
		if j.snapshot.InputEnded && j.frames.count == 0 {
			g.finishCompleted(j)
			continue
		}
		if !g.transport.ReadyState() {
			g.setState(j, wire.PlaybackState_PLAYBACK_STATE_QUEUED, wire.PlaybackReason_PLAYBACK_REASON_WAITING_DAVE)
			j.idleSince = time.Time{}
			continue
		}
		if j.frames.count == 0 {
			g.setState(j, wire.PlaybackState_PLAYBACK_STATE_QUEUED, wire.PlaybackReason_PLAYBACK_REASON_WAITING_INPUT)
			if preferred(j, waiting) {
				waiting = j
			}
			continue
		}
		if preferred(j, best) {
			best = j
		}
	}
	if best == nil {
		for _, j := range g.jobs {
			if j != waiting {
				j.idleSince = time.Time{}
			}
		}
		if waiting != nil {
			g.renew(waiting)
		}
		return
	}
	for _, j := range g.jobs {
		if j != best && !j.paused {
			if j.frames.count > 0 {
				reason := wire.PlaybackReason_PLAYBACK_REASON_WAITING_PRIORITY
				if j.snapshot.State == wire.PlaybackState_PLAYBACK_STATE_RUNNING {
					reason = wire.PlaybackReason_PLAYBACK_REASON_PREEMPTED
				}
				g.setState(j, wire.PlaybackState_PLAYBACK_STATE_QUEUED, reason)
			}
			j.idleSince = time.Time{}
		}
	}
	g.setState(best, wire.PlaybackState_PLAYBACK_STATE_RUNNING, wire.PlaybackReason_PLAYBACK_REASON_PLAYING)
	g.renew(best)
	if best.stopping != nil {
		return
	}
	g.inflight = best
	g.inflightFrame = best.frames.pop()
	g.handed = false
	packet := g.inflightFrame.opus
	go g.submit(best, packet)
}
func (g *guild) submit(j *job, packet []byte) {
	ctx, cancel := context.WithTimeout(g.ctx, g.service.config.SubmissionTimeout)
	submission, err := g.transport.SubmitOpus(ctx, packet)
	cancel()
	if err != nil {
		g.sent <- sendResult{j: j, err: err, bytes: len(packet)}
		return
	}
	g.sent <- sendResult{j: j, handed: true}
	timer := time.NewTimer(g.service.config.ReceiptTimeout)
	defer timer.Stop()
	select {
	case r, ok := <-submission.Done():
		if !ok {
			g.sent <- sendResult{j: j, err: failure(codes.Internal, wire.VoiceErrorReason_VOICE_ERROR_REASON_INTERNAL, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_UDP_WRITE), bytes: len(packet)}
		} else {
			g.sent <- sendResult{j: j, err: r.Err, bytes: len(packet)}
		}
	case <-timer.C:
		g.sent <- sendResult{j: j, err: timeout(wire.VoiceErrorReason_VOICE_ERROR_REASON_RECEIPT_TIMEOUT, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_UDP_WRITE), bytes: len(packet)}
	}
}
func (g *guild) onSend(r sendResult) {
	j := g.inflight
	if j == nil || j != r.j {
		return
	}
	if r.handed {
		g.handed = true
		j.snapshot.LastSubmittedSequence = g.inflightFrame.sequence
		g.publish(j)
		return
	}
	if r.err != nil && !g.handed && errors.Is(r.err, discordgo.ErrVoiceNotReady) && !g.closing && j.stopping == nil {
		j.frames.pushFront(g.inflightFrame)
		g.inflight = nil
		g.inflightFrame = frame{}
		j.idleSince = time.Time{}
		g.setState(j, wire.PlaybackState_PLAYBACK_STATE_QUEUED, wire.PlaybackReason_PLAYBACK_REASON_WAITING_DAVE)
		return
	}
	if r.err != nil {
		stage := wire.VoiceFailureStage_VOICE_FAILURE_STAGE_UDP_WRITE
		if !g.handed {
			stage = wire.VoiceFailureStage_VOICE_FAILURE_STAGE_SUBMISSION
		}
		e := transportFailure(r.err, stage)
		e.detail.MayHaveSubmitted = g.handed
		g.forceClose = true
		g.failAll(e)
		g.startAbort()
		return
	}
	j.snapshot.LastUdpWrittenSequence = g.inflightFrame.sequence
	g.service.releaseFrames(j, 1, int64(r.bytes))
	g.inflight = nil
	g.inflightFrame = frame{}
	g.publish(j)
	if j.stopping != nil {
		g.finishJob(j)
	} else if j.pausing {
		j.paused = true
		j.pausing = false
		g.setState(j, wire.PlaybackState_PLAYBACK_STATE_PAUSED, wire.PlaybackReason_PLAYBACK_REASON_OWNER_PAUSED)
		g.notifyWaiters(j)
	}
}
func (g *guild) startClose() {
	if g.closeStarted || g.stateBusy || g.inflight != nil || len(g.jobs) != 0 || len(g.subs) != 0 || g.aborting || g.abortWaiting {
		return
	}
	g.closeStarted = true
	if g.transport == nil {
		return
	}
	v := g.transport
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), g.service.config.Transport.CloseTimeout)
		defer cancel()
		g.closed <- v.DisconnectContext(ctx)
	}()
}
func (g *guild) remove() bool {
	s := g.service
	s.mu.Lock()
	if g.admissions != 0 {
		s.mu.Unlock()
		return false
	}
	if s.guilds[g.id] == g {
		delete(s.guilds, g.id)
		if g.closingOwner != "" {
			if i := s.instances[g.closingOwner]; i != nil {
				i.usage.sessions--
			}
			g.closingOwner = ""
		}
	}
	s.pruneLocked(time.Now())
	s.signalLocked()
	s.mu.Unlock()
	return true
}
func (g *guild) receive(v Transport, packets chan<- *discordgo.Packet, failures chan<- error) {
	for {
		p, err := v.ReceiveOpus(g.ctx)
		if err != nil {
			select {
			case failures <- err:
			case <-g.done:
			}
			return
		}
		if p == nil {
			continue
		}
		select {
		case packets <- p:
		case <-v.Done():
			clear(p.Opus)
			return
		case <-g.done:
			clear(p.Opus)
			return
		}
	}
}
func (g *guild) setState(j *job, state wire.PlaybackState, reason wire.PlaybackReason) {
	if j.snapshot.State != state || j.snapshot.Reason != reason {
		j.snapshot.State = state
		j.snapshot.Reason = reason
		g.publish(j)
	}
}
func (g *guild) publish(j *job) {
	snapshot := proto.Clone(j.snapshot).(*wire.PlaybackSnapshot)
	select {
	case j.status <- snapshot:
	default:
		select {
		case <-j.status:
		default:
		}
		select {
		case j.status <- snapshot:
		default:
		}
	}
	s := g.service
	s.mu.Lock()
	if r := s.jobs[j.id]; r != nil {
		r.view = snapshot
	}
	s.bumpLocked(g.id)
	s.mu.Unlock()
}
func (g *guild) renew(j *job) {
	if j.paused || j.pausing || j.stopping != nil || j.snapshot.InputEnded {
		return
	}
	targetBytes := int64(g.service.config.InitialCreditFrames) * int64(g.service.config.MaxOpusPacketBytes)
	for j.resFrames < g.service.config.InitialCreditFrames {
		addBytes := targetBytes - j.resBytes
		if addBytes > int64(g.service.config.MaxOpusPacketBytes) {
			addBytes = int64(g.service.config.MaxOpusPacketBytes)
		}
		if addBytes < 0 {
			addBytes = 0
		}
		if j.snapshot.CreditThroughSequence == math.MaxUint64 || j.snapshot.CreditThroughBytes > math.MaxUint64-uint64(addBytes) {
			g.stopJob(j, failure(codes.InvalidArgument, wire.VoiceErrorReason_VOICE_ERROR_REASON_SEQUENCE_EXHAUSTED, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_INPUT), false)
			return
		}
		if !g.service.reserveFrames(j, 1, addBytes) {
			break
		}
		j.snapshot.CreditThroughSequence++
		j.snapshot.CreditThroughBytes += uint64(addBytes)
		g.publish(j)
	}
	if j.bound && j.snapshot.CreditThroughSequence > j.snapshot.LastAcceptedSequence && j.snapshot.CreditThroughBytes-j.acceptedBytes >= uint64(g.service.config.MaxOpusPacketBytes) {
		if j.idleSince.IsZero() {
			j.idleSince = time.Now()
		}
	} else {
		j.idleSince = time.Time{}
	}
}
func (g *guild) stopJob(j *job, e *voiceFailure, cancelled bool) {
	if j.stopping == nil {
		j.stopping = e
		j.cancelState = cancelled
		j.frames.clear()
		j.idleSince = time.Time{}
	}
	if g.inflight != j {
		g.finishJob(j)
	}
}
func (g *guild) finishCompleted(j *job) {
	if j.snapshot.InputEnded && j.snapshot.FinalSequence == j.snapshot.LastAcceptedSequence && j.snapshot.LastUdpWrittenSequence == j.snapshot.FinalSequence {
		j.snapshot.State = wire.PlaybackState_PLAYBACK_STATE_COMPLETED
		j.snapshot.Reason = wire.PlaybackReason_PLAYBACK_REASON_INPUT_DRAINED
		g.finishJob(j)
	}
}
func (g *guild) finishJob(j *job) {
	if _, ok := g.jobs[j.id]; !ok || g.inflight == j {
		return
	}
	if j.stopping != nil {
		j.snapshot.State = wire.PlaybackState_PLAYBACK_STATE_FAILED
		j.snapshot.Reason = wire.PlaybackReason_PLAYBACK_REASON_ERROR
		if j.cancelState {
			j.snapshot.State = wire.PlaybackState_PLAYBACK_STATE_CANCELLED
			j.snapshot.Reason = wire.PlaybackReason_PLAYBACK_REASON_OWNER_CANCELLED
			switch j.stopping.detail.Reason {
			case wire.VoiceErrorReason_VOICE_ERROR_REASON_STREAM_CANCELLED:
				j.snapshot.Reason = wire.PlaybackReason_PLAYBACK_REASON_STREAM_CANCELLED
			case wire.VoiceErrorReason_VOICE_ERROR_REASON_INSTANCE_STOPPED:
				j.snapshot.Reason = wire.PlaybackReason_PLAYBACK_REASON_INSTANCE_STOPPED
			}
		}
		d := proto.Clone(j.stopping.detail).(*wire.VoiceError)
		d.JobId = j.id
		d.GuildId = g.id
		d.ChannelId = g.channel
		d.MayHaveSubmitted = j.snapshot.LastSubmittedSequence > j.snapshot.LastUdpWrittenSequence
		j.snapshot.TerminalError = d
	}
	if !terminal(j.snapshot.State) {
		return
	}
	g.service.releaseFrames(j, j.resFrames, j.resBytes)
	j.frames.clear()
	delete(g.jobs, j.id)
	g.releaseOwner(j.owner, true)
	g.publish(j)
	close(j.terminalDone)
	g.notifyWaiters(j)
	s := g.service
	s.mu.Lock()
	if r := s.jobs[j.id]; r != nil {
		r.final = r.view
		r.view = nil
		r.actor = nil
		r.at = time.Now()
	}
	s.pruneLocked(time.Now())
	s.notifyRecordsLocked()
	s.signalLocked()
	s.mu.Unlock()
	if !j.bound || j.streamEnded {
		g.releaseStatus(j)
	}
}
func (g *guild) notifyWaiters(j *job) {
	if len(j.waiters) == 0 {
		return
	}
	s := g.service
	s.mu.Lock()
	published := s.jobs[j.id].view
	s.mu.Unlock()
	for _, ch := range j.waiters {
		ch <- answer{value: published}
	}
	j.waiters = nil
}
func (g *guild) releaseOwner(p rt.InstancePrincipal, job bool) {
	s := g.service
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.instances[p.InstanceID]
	if job {
		s.usage.jobs--
		if i != nil {
			i.usage.jobs--
		}
	} else {
		s.usage.subs--
		if i != nil {
			i.usage.subs--
		}
	}
	g.owners[p.InstanceID]--
	if g.owners[p.InstanceID] == 0 {
		delete(g.owners, p.InstanceID)
		if len(g.jobs) == 0 && len(g.subs) == 0 && g.inflight == nil {
			g.closingOwner = p.InstanceID
		} else if i != nil {
			i.usage.sessions--
		}
	}
	s.signalLocked()
}
func (g *guild) failAll(e *voiceFailure) {
	g.retiring = false
	g.closing = true
	for _, j := range g.jobs {
		g.stopJob(j, e, false)
	}
	for _, v := range g.subs {
		g.finishSub(v, e)
	}
	if g.inflight == nil && !g.joining {
		g.startClose()
	}
}
func (g *guild) cleanupOwner(p rt.InstancePrincipal) {
	for _, j := range g.jobs {
		if j.owner == p {
			g.stopJob(j, stopped(), true)
		}
	}
	for _, v := range g.subs {
		if v.owner == p {
			g.finishSub(v, stopped())
		}
	}
}
func (g *guild) deadline() time.Time {
	var d time.Time
	for _, j := range g.jobs {
		if j.stopping != nil {
			continue
		}
		d = earlier(d, j.snapshot.ExpiresAt.AsTime())
		if !j.bound {
			d = earlier(d, j.firstBind)
		}
		if !j.idleSince.IsZero() {
			d = earlier(d, j.idleSince.Add(g.service.config.InputIdleTimeout))
		}
	}
	for _, v := range g.subs {
		if !v.terminal {
			d = earlier(d, v.snapshot.ExpiresAt.AsTime())
		}
		if !v.pendingSince.IsZero() {
			d = earlier(d, v.pendingSince.Add(g.service.config.SlowConsumerTimeout))
		}
	}
	return d
}
func (g *guild) expire(now time.Time) {
	for _, j := range g.jobs {
		if j.stopping != nil {
			continue
		}
		var e *voiceFailure
		if !now.Before(j.snapshot.ExpiresAt.AsTime()) {
			e = timeout(wire.VoiceErrorReason_VOICE_ERROR_REASON_LIFETIME_EXCEEDED, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_INPUT)
		} else if !j.bound && !now.Before(j.firstBind) {
			e = timeout(wire.VoiceErrorReason_VOICE_ERROR_REASON_BIND_TIMEOUT, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_BIND)
		} else if !j.idleSince.IsZero() && !now.Before(j.idleSince.Add(g.service.config.InputIdleTimeout)) {
			e = timeout(wire.VoiceErrorReason_VOICE_ERROR_REASON_INPUT_TIMEOUT, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_INPUT)
		}
		if e != nil {
			g.stopJob(j, e, false)
		}
	}
	for _, v := range g.subs {
		if !v.terminal && !now.Before(v.snapshot.ExpiresAt.AsTime()) {
			g.finishSub(v, timeout(wire.VoiceErrorReason_VOICE_ERROR_REASON_LIFETIME_EXCEEDED, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_RECEIVE))
		} else if !v.pendingSince.IsZero() && !now.Before(v.pendingSince.Add(g.service.config.SlowConsumerTimeout)) {
			if v.terminal {
				g.releaseSub(v)
			} else {
				g.finishSub(v, timeout(wire.VoiceErrorReason_VOICE_ERROR_REASON_RECEIVE_TIMEOUT, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_RECEIVE))
			}
		}
	}
}
func snapshot(j *job) *wire.PlaybackSnapshot { return proto.Clone(j.snapshot).(*wire.PlaybackSnapshot) }
func newSnapshot(id, guild, channel string, priority int32, lifetime time.Duration) *wire.PlaybackSnapshot {
	return &wire.PlaybackSnapshot{JobId: id, GuildId: guild, ChannelId: channel, Priority: priority, State: wire.PlaybackState_PLAYBACK_STATE_QUEUED, Reason: wire.PlaybackReason_PLAYBACK_REASON_WAITING_CONNECTION, ExpiresAt: timestamppb.New(time.Now().Add(lifetime))}
}

var errDeferred = &deferred{}

type deferred struct{}

func (*deferred) Error() string { return "actor reply deferred to receipt boundary" }
func preferred(a, b *job) bool {
	return b == nil || a.snapshot.Priority > b.snapshot.Priority || a.snapshot.Priority == b.snapshot.Priority && a.ordinal < b.ordinal
}
func (s *Service) changedSignal() <-chan struct{} { s.mu.Lock(); defer s.mu.Unlock(); return s.changed }
func (g *guild) activateReceivers() {
	if g.transport == nil || !g.transport.ReadyState() {
		return
	}
	for _, v := range g.subs {
		if !v.terminal && v.snapshot.State == wire.VoiceSubscriptionState_VOICE_SUBSCRIPTION_STATE_JOINING {
			v.snapshot.State = wire.VoiceSubscriptionState_VOICE_SUBSCRIPTION_STATE_ACTIVE
			g.subEvent(v, readyEvent(v.snapshot))
		}
	}
}

// Abort only the local sender/native owners first. Its immutable frame and quota
// remain owned until CloseContext succeeds or Done proves joined destruction.
// Main-Gateway disconnect is a separate last-reference operation.
func (g *guild) startAbort() {
	if g.aborting || g.abortWaiting || g.stateBusy || len(g.subs) != 0 || g.transport == nil {
		return
	}
	g.aborting = true
	v := g.transport
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), g.service.config.Transport.CloseTimeout)
		defer cancel()
		g.aborted <- v.CloseContext(ctx)
	}()
}
func (g *guild) finishAbort() {
	g.abortWaiting = false
	g.forceClose = false
	if j := g.inflight; j != nil {
		g.inflight = nil
		g.inflightFrame = frame{}
		if g.abortFailure != nil {
			j.stopping = g.abortFailure
			j.cancelState = false
		}
		g.finishJob(j)
	}
	g.abortFailure = nil
}
func (g *guild) recordCleanupError(err error) {
	g.cleanupErr = err
	g.service.mu.Lock()
	g.service.cleanupErr = err
	g.service.mu.Unlock()
}
func (g *guild) onAbort(err error) {
	g.aborting = false
	if err == nil {
		g.finishAbort()
		return
	}
	g.abortFailure = transportFailure(err, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CLEANUP)
	g.recordCleanupError(g.abortFailure)
	select {
	case <-g.transport.Done():
		g.finishAbort()
	default:
		g.abortWaiting = true
	}
}
func (g *guild) cleanupJoined() {
	if g.abortWaiting {
		g.finishAbort()
	} else {
		g.disconnectWaiting = false
		g.transport = nil
	}
}
func (g *guild) onDisconnect(err error) {
	if err == nil {
		g.transport = nil
		g.received = nil
		g.receiveError = nil
		g.finishRetirement()
		return
	}
	e := transportFailure(err, wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CLEANUP)
	g.recordCleanupError(e)
	g.failAll(e)
	select {
	case <-g.transport.Done():
		g.transport = nil
	default:
		g.disconnectWaiting = true
	}
}

func (g *guild) finishRetirement() {
	if g.retiring && !g.shutting && g.cleanupErr == nil && g.transport == nil && !g.joining && len(g.jobs) != 0 {
		// The old generation has joined local owners and consumed its ordered
		// leave. Admissions pinned across actor removal may now acquire afresh.
		g.retiring = false
		g.closing = false
		g.closeStarted = false
	}
}
