package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	provider "github.com/thirdscam/chatanium/modules/music-bot/provider"
	discord "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type playbackAPI interface {
	CreatePlaybackJob(context.Context, discord.CreatePlaybackJobRequest) (discord.PlaybackSnapshot, error)
	ProducePlayback(context.Context, discord.JobRequest, uint64, func(context.Context) ([]byte, error)) (discord.PlaybackSnapshot, error)
	PausePlaybackJob(context.Context, discord.JobRequest) (discord.PlaybackSnapshot, error)
	ResumePlaybackJob(context.Context, discord.JobRequest) (discord.PlaybackSnapshot, error)
	CancelPlaybackJob(context.Context, discord.JobRequest) (discord.PlaybackSnapshot, error)
}
type PlaylistEntry struct {
	ID        string
	Title     string
	State     string
	JobID     discord.JobID
	LastError string
}
type PlaylistSnapshot struct {
	Current   *PlaylistEntry
	Waiting   []PlaylistEntry
	Loop      bool
	LastError string
}
type playlistItem struct {
	view         PlaylistEntry
	track        provider.Track
	query        string
	textChannel  string
	voiceChannel string
	resolving    bool
	dispatched   bool
	reserved     int
	audio        *PreparedAudio
	ctx          context.Context
	cancel       context.CancelFunc
}
type playlistCommand struct {
	ctx          context.Context
	op           string
	query        string
	channel      string
	voiceChannel string
	entryID      string
	enabled      bool
	reply        chan playlistReply
}
type playlistReply struct {
	snapshot PlaylistSnapshot
	entryID  string
	playback discord.PlaybackSnapshot
	err      error
}
type prepareTask struct {
	owner     *Playlist
	id        string
	ctx       context.Context
	query     string
	track     provider.Track
	resolving bool
}
type prepareResult struct {
	id     string
	tracks []provider.Track
	audio  *PreparedAudio
	err    error
}
type playEvent struct {
	created  bool
	ack      chan struct{}
	snapshot discord.PlaybackSnapshot
	err      error
}
type Playlist struct {
	ctx             context.Context
	cancel          context.CancelFunc
	cleanupMu       sync.Mutex
	cleanupDeadline time.Time
	guild           string
	limits          MediaLimits
	priority        int32
	voice           playbackAPI
	provider        provider.Provider
	preparer        *Preparer
	tasks           chan<- prepareTask
	commands        chan playlistCommand
	results         chan prepareResult
	playback        chan playEvent
	done            chan struct{}
	notify          func(context.Context, string, string) error
	// The following fields have exactly one owner: run.
	waiting       []*playlistItem
	current       *playlistItem
	currentJob    discord.PlaybackSnapshot
	currentCancel context.CancelFunc
	playDone      chan struct{}
	skipReply     chan playlistReply
	inFlight      int
	loop          bool
	closing       bool
	failure       error
	lastError     string
	serial        uint64
	used          int
}

func newPlaylist(ctx context.Context, guild string, limits MediaLimits, priority int32, voice playbackAPI, p provider.Provider, preparer *Preparer, tasks chan<- prepareTask, notify func(context.Context, string, string) error) *Playlist {
	ctx, cancel := context.WithCancel(ctx)
	return &Playlist{ctx: ctx, cancel: cancel, guild: guild, limits: limits, priority: priority, voice: voice, provider: p, preparer: preparer, tasks: tasks, commands: make(chan playlistCommand, limits.MailboxEntries), results: make(chan prepareResult, limits.Workers), playback: make(chan playEvent, 1), done: make(chan struct{}), notify: notify}
}
func (p *Playlist) call(ctx context.Context, c playlistCommand) (playlistReply, error) {
	c.ctx = ctx
	c.reply = make(chan playlistReply, 1)
	select {
	case <-ctx.Done():
		return playlistReply{}, ctx.Err()
	case <-p.done:
		return playlistReply{}, errors.New("playlist closed")
	case p.commands <- c:
	default:
		return playlistReply{}, errors.New("playlist command mailbox full")
	}
	select {
	case <-ctx.Done():
		return playlistReply{}, ctx.Err()
	case <-p.done:
		return playlistReply{}, errors.New("playlist closed")
	case result := <-c.reply:
		return result, result.err
	}
}
func (p *Playlist) Enqueue(ctx context.Context, query, textChannel, voiceChannel string) (string, error) {
	r, e := p.call(ctx, playlistCommand{op: "enqueue", query: query, channel: textChannel, voiceChannel: voiceChannel})
	return r.entryID, e
}
func (p *Playlist) Snapshot(ctx context.Context) (PlaylistSnapshot, error) {
	r, e := p.call(ctx, playlistCommand{op: "snapshot"})
	return r.snapshot, e
}
func (p *Playlist) Remove(ctx context.Context, entryID string) error {
	_, e := p.call(ctx, playlistCommand{op: "remove", entryID: entryID})
	return e
}
func (p *Playlist) Pause(ctx context.Context) (discord.PlaybackSnapshot, error) {
	r, e := p.call(ctx, playlistCommand{op: "pause"})
	return r.playback, e
}
func (p *Playlist) Resume(ctx context.Context) (discord.PlaybackSnapshot, error) {
	r, e := p.call(ctx, playlistCommand{op: "resume"})
	return r.playback, e
}
func (p *Playlist) Skip(ctx context.Context) error {
	_, e := p.call(ctx, playlistCommand{op: "skip"})
	return e
}
func (p *Playlist) SetLoop(ctx context.Context, enabled bool) error {
	_, e := p.call(ctx, playlistCommand{op: "loop", enabled: enabled})
	return e
}
func (p *Playlist) Close(ctx context.Context) error {
	p.beginClose(ctx)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
		return p.failure
	}
}
func (p *Playlist) beginClose(ctx context.Context) {
	deadline := time.Now().Add(millis(p.limits.CommandTimeoutMS))
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if ctx.Err() != nil {
		deadline = time.Now()
	}
	p.cleanupMu.Lock()
	if p.cleanupDeadline.IsZero() || deadline.Before(p.cleanupDeadline) {
		p.cleanupDeadline = deadline
	}
	p.cleanupMu.Unlock()
	p.cancel()
}
func (p *Playlist) cleanupContext() (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(millis(p.limits.CommandTimeoutMS))
	p.cleanupMu.Lock()
	if !p.cleanupDeadline.IsZero() && p.cleanupDeadline.Before(deadline) {
		deadline = p.cleanupDeadline
	}
	p.cleanupMu.Unlock()
	return context.WithDeadline(context.Background(), deadline)
}
func (p *Playlist) nextID() string { p.serial++; return strconv.FormatUint(p.serial, 10) }
func (p *Playlist) snapshot() PlaylistSnapshot {
	s := PlaylistSnapshot{Loop: p.loop, LastError: p.lastError, Waiting: make([]PlaylistEntry, len(p.waiting))}
	if p.current != nil {
		v := p.current.view
		s.Current = &v
	}
	for i, item := range p.waiting {
		s.Waiting[i] = item.view
	}
	return s
}
func (p *Playlist) run() {
	defer close(p.done)
	for {
		p.advance()
		var send chan<- prepareTask
		var task prepareTask
		if !p.closing && p.failure == nil {
			for _, entry := range p.waiting {
				if entry.view.State == "PREPARING" && !entry.dispatched {
					send = p.tasks
					task = prepareTask{owner: p, id: entry.view.ID, ctx: entry.ctx, query: entry.query, track: entry.track, resolving: entry.resolving}
					break
				}
			}
		}
		select {
		case <-p.ctx.Done():
			p.shutdown()
			return
		case send <- task:
			p.inFlight++
			for _, entry := range p.waiting {
				if entry.view.ID == task.id {
					entry.dispatched = true
					break
				}
			}
		case command := <-p.commands:
			p.handle(command)
		case result := <-p.results:
			p.inFlight--
			p.prepared(result)
		case event := <-p.playback:
			p.played(event)
		}
	}
}
func (p *Playlist) handle(c playlistCommand) {
	r := playlistReply{}
	if err := c.ctx.Err(); err != nil {
		r.err = err
		c.reply <- r
		return
	}
	if c.op == "snapshot" {
		r.snapshot = p.snapshot()
		c.reply <- r
		return
	}
	if p.closing || p.failure != nil {
		r.err = errors.Join(errors.New("playlist not accepting work"), p.failure)
		c.reply <- r
		return
	}
	switch c.op {
	case "enqueue":
		if len(c.query) == 0 || len(c.query) > p.limits.MaxQueryBytes {
			r.err = errors.New("query is empty or exceeds limit")
			break
		}
		if p.used > p.limits.QueueEntries-p.limits.MaxResults {
			r.err = errors.New("playlist queue capacity exceeded")
			break
		}
		ctx, cancel := context.WithTimeout(p.ctx, millis(p.limits.QueueTimeoutMS))
		id := p.nextID()
		p.waiting = append(p.waiting, &playlistItem{view: PlaylistEntry{ID: id, Title: "Resolving request", State: "PREPARING"}, query: c.query, textChannel: c.channel, voiceChannel: c.voiceChannel, resolving: true, reserved: p.limits.MaxResults, ctx: ctx, cancel: cancel})
		p.used += p.limits.MaxResults
		r.entryID = id
	case "remove":
		if p.current != nil && p.current.view.ID == c.entryID {
			r.err = errors.New("current entry must be skipped, not removed")
			break
		}
		index := -1
		for i, item := range p.waiting {
			if item.view.ID == c.entryID {
				index = i
				break
			}
		}
		if index < 0 {
			r.err = errors.New("waiting entry not found")
			break
		}
		item := p.waiting[index]
		item.cancel()
		if item.audio != nil {
			r.err = item.audio.Release()
			p.failure = errors.Join(p.failure, r.err)
		}
		p.used -= item.reserved
		p.waiting = append(p.waiting[:index], p.waiting[index+1:]...)
	case "loop":
		p.loop = c.enabled
	case "pause", "resume", "skip":
		if p.current == nil || p.currentJob.JobID == "" {
			r.err = errors.New("no bound current playback job")
			break
		}
		if p.skipReply != nil {
			r.err = errors.New("skip already awaiting terminal playback")
			break
		}
		job := discord.JobRequest{JobID: p.currentJob.JobID}
		switch c.op {
		case "pause":
			r.playback, r.err = p.voice.PausePlaybackJob(c.ctx, job)
		case "resume":
			r.playback, r.err = p.voice.ResumePlaybackJob(c.ctx, job)
		case "skip":
			r.playback, r.err = p.voice.CancelPlaybackJob(c.ctx, job)
			if r.err == nil && !r.playback.Terminal() {
				r.err = errors.New("cancel returned before terminal boundary")
			}
			if r.err == nil {
				p.skipReply = c.reply
				return
			}
		}
		if r.err == nil {
			p.currentJob = r.playback
			p.current.view.State = r.playback.State.String()
		}
	default:
		r.err = errors.New("unknown playlist operation")
	}
	c.reply <- r
}
func (p *Playlist) prepared(result prepareResult) {
	index := -1
	for i, item := range p.waiting {
		if item.view.ID == result.id {
			index = i
			break
		}
	}
	if index < 0 {
		if result.audio != nil {
			releaseErr := result.audio.Release()
			p.failure = errors.Join(p.failure, releaseErr)
			p.recordError("", releaseErr)
		}
		return
	}
	item := p.waiting[index]
	if result.err != nil {
		item.view.State = "FAILED"
		item.view.LastError = result.err.Error()
		item.cancel()
		p.recordError(item.textChannel, result.err)
		if item.audio != nil {
			releaseErr := item.audio.Release()
			p.failure = errors.Join(p.failure, releaseErr)
			p.recordError(item.textChannel, releaseErr)
		}
		if result.audio != nil {
			releaseErr := result.audio.Release()
			p.failure = errors.Join(p.failure, releaseErr)
			p.recordError(item.textChannel, releaseErr)
		}
		p.used -= item.reserved
		p.waiting = append(p.waiting[:index], p.waiting[index+1:]...)
		return
	}
	if item.resolving {
		if len(result.tracks) == 0 || len(result.tracks) > item.reserved {
			p.prepared(prepareResult{id: result.id, err: errors.New("invalid bounded provider result")})
			return
		}
		replacements := make([]*playlistItem, 0, len(result.tracks))
		for _, track := range result.tracks {
			ctx, cancel := context.WithTimeout(p.ctx, millis(p.limits.QueueTimeoutMS))
			replacements = append(replacements, &playlistItem{view: PlaylistEntry{ID: p.nextID(), Title: track.Title, State: "PREPARING"}, track: track, textChannel: item.textChannel, voiceChannel: item.voiceChannel, reserved: 1, ctx: ctx, cancel: cancel})
		}
		item.cancel()
		p.used -= item.reserved - len(replacements)
		tail := append([]*playlistItem{}, p.waiting[index+1:]...)
		p.waiting = append(append(p.waiting[:index], replacements...), tail...)
	} else {
		if result.audio == nil {
			p.prepared(prepareResult{id: result.id, err: errors.New("preparation returned no complete artifact")})
			return
		}
		item.audio = result.audio
		item.view.State = "READY"
	}
}
func (p *Playlist) advance() {
	for len(p.waiting) > 0 && p.waiting[0].ctx.Err() != nil {
		item := p.waiting[0]
		p.prepared(prepareResult{id: item.view.ID, err: item.ctx.Err()})
	}
	if p.closing || p.failure != nil || p.current != nil || len(p.waiting) == 0 || p.waiting[0].view.State != "READY" {
		return
	}
	item := p.waiting[0]
	p.waiting = p.waiting[1:]
	p.current = item
	item.view.State = "CREATING_JOB"
	ctx, cancel := context.WithTimeout(p.ctx, millis(p.limits.PlaybackTimeoutMS))
	p.currentCancel = cancel
	p.playDone = make(chan struct{})
	go p.play(ctx, item, p.playDone)
}
func (p *Playlist) play(ctx context.Context, item *playlistItem, done chan struct{}) {
	defer close(done)
	snapshot, err := p.voice.CreatePlaybackJob(ctx, discord.CreatePlaybackJobRequest{GuildID: p.guild, ChannelID: item.voiceChannel, Priority: p.priority, Lifetime: millis(p.limits.PlaybackTimeoutMS), Format: discord.Opus48kHz20ms})
	if err == nil {
		ack := make(chan struct{})
		select {
		case p.playback <- playEvent{created: true, ack: ack, snapshot: snapshot}:
			select {
			case <-ack:
			case <-ctx.Done():
			}
		case <-ctx.Done():
		}
		if ctx.Err() == nil {
			terminal, playErr := PlayPrepared(ctx, p.voice, item.audio, discord.JobRequest{JobID: snapshot.JobID}, p.limits.MaxPacketBytes)
			if terminal.JobID != "" {
				snapshot = terminal
			}
			err = playErr
		} else {
			err = ctx.Err()
		}
	}
	// A failed stream or producer must still release the real job. A lost create
	// response is not retried; without a known terminal the actor never advances.
	if snapshot.JobID != "" && !snapshot.Terminal() {
		cleanup, cancel := p.cleanupContext()
		terminal, e := p.voice.CancelPlaybackJob(cleanup, discord.JobRequest{JobID: snapshot.JobID})
		cancel()
		err = errors.Join(err, e)
		if e == nil {
			snapshot = terminal
		}
	}
	p.playback <- playEvent{snapshot: snapshot, err: err}
}
func (p *Playlist) played(event playEvent) {
	if event.created {
		p.currentJob = event.snapshot
		if p.current != nil {
			p.current.view.JobID = event.snapshot.JobID
			p.current.view.State = "PLAYING"
		}
		close(event.ack)
		return
	}
	<-p.playDone
	item := p.current
	if item == nil {
		return
	}
	p.currentCancel()
	p.currentCancel = nil
	p.currentJob = event.snapshot
	err := event.err
	if event.snapshot.State == discord.PlaybackCancelled && (p.skipReply != nil || p.closing) {
		err = withoutCancellation(err)
	}
	if !event.snapshot.Terminal() {
		err = errors.Join(err, errors.New("playback terminal boundary unconfirmed"))
		p.failure = err
	}
	if event.snapshot.State == discord.PlaybackFailed && err == nil {
		err = errors.New("playback failed")
	}
	if err != nil {
		p.recordError(item.textChannel, err)
		if p.closing {
			p.failure = errors.Join(p.failure, err)
		}
	}
	// ProducePlayback closed its reader before this event. Requeue only COMPLETED;
	// priority preemption never produces a terminal event or replaces this entry.
	if p.loop && event.snapshot.State == discord.PlaybackCompleted && err == nil && !p.closing && p.skipReply == nil {
		item.cancel()
		item.ctx, item.cancel = context.WithTimeout(p.ctx, millis(p.limits.QueueTimeoutMS))
		item.view.State = "READY"
		item.view.JobID = ""
		p.waiting = append(p.waiting, item)
	} else {
		item.cancel()
		releaseErr := item.audio.Release()
		p.failure = errors.Join(p.failure, releaseErr)
		err = errors.Join(err, releaseErr)
		p.recordError(item.textChannel, releaseErr)
		p.used -= item.reserved
	}
	p.current = nil
	p.currentJob = discord.PlaybackSnapshot{}
	if p.skipReply != nil {
		p.skipReply <- playlistReply{err: err}
		p.skipReply = nil
	}
}
func withoutCancellation(err error) error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var remaining error
		for _, cause := range joined.Unwrap() {
			remaining = errors.Join(remaining, withoutCancellation(cause))
		}
		return remaining
	}
	if errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled {
		return nil
	}
	return err
}
func (p *Playlist) recordError(channel string, err error) {
	if err == nil {
		return
	}
	p.lastError = err.Error()
	if channel != "" && p.notify != nil {
		ctx, cancel := context.WithTimeout(p.ctx, millis(p.limits.CommandTimeoutMS))
		report := p.notify(ctx, channel, "Music task failed. Use /list for task state.")
		cancel()
		if report != nil {
			p.lastError = errors.Join(err, fmt.Errorf("error reporting failed: %w", report)).Error()
		}
	}
}
func (p *Playlist) shutdown() {
	p.closing = true
	for _, item := range p.waiting {
		item.cancel()
		if item.audio != nil {
			p.failure = errors.Join(p.failure, item.audio.Release())
		}
	}
	p.waiting = nil
	for p.inFlight > 0 {
		result := <-p.results
		p.inFlight--
		if result.audio != nil {
			p.failure = errors.Join(p.failure, result.audio.Release())
		}
	}
	if p.current != nil {
		p.currentCancel()
		// The playback worker owns stream+reader cleanup. Continue consuming its
		// create handshake until the terminal result so no lease is released early.
		for {
			event := <-p.playback
			if event.created {
				close(event.ack)
				continue
			}
			p.played(event)
			break
		}
		<-p.playDone
	}
	if p.skipReply != nil {
		p.skipReply <- playlistReply{err: errors.New("playlist drained")}
		p.skipReply = nil
	}
}
func runPreparationWorkers(ctx context.Context, count int, tasks <-chan prepareTask, wait *sync.WaitGroup) {
	for range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case task := <-tasks:
					result := prepareResult{id: task.id}
					if task.resolving {
						result.tracks, result.err = task.owner.provider.Resolve(task.ctx, task.query)
					} else {
						result.audio, result.err = task.owner.preparer.Prepare(task.ctx, task.track)
					}
					task.owner.results <- result
				}
			}
		}()
	}
}
