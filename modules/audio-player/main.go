package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/hashicorp/go-plugin"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	discordwire "github.com/thirdscam/chatanium/proto/discord-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	discord "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

//go:embed manifest.json
var manifestJSON []byte

type attachmentRequest struct {
	guild, channel, voice string
	attachment            attachment
}

type player struct {
	mu                                  sync.Mutex
	core                                core.CoreClient
	discord                             *discord.Client
	voice                               *discord.VoiceClient
	lifetime                            context.Context
	cancel                              context.CancelFunc
	cfg                                 playerConfig
	ready, started, validated, draining bool
	failure                             error
	scratch                             *scratchSpace
	downloads                           *attachmentDownloader
	queue                               chan attachmentRequest
	slots                               chan struct{}
	wg                                  sync.WaitGroup
	done                                chan struct{}
	cleanupDeadline                     time.Time
	cleanupError                        error
}

func newPlayer(lifetime context.Context) *player {
	ctx, cancel := context.WithCancel(lifetime)
	return &player{lifetime: ctx, cancel: cancel}
}

func (p *player) bind(_ context.Context, conn grpc.ClientConnInterface) (err error) {
	p.core, err = core.NewCoreClient(conn, core.JSONLimits{MaxBytes: 64 * 1024, MaxDepth: 16})
	if err != nil {
		return err
	}
	p.discord, err = discord.NewClient(conn)
	if err != nil {
		return err
	}
	p.voice, err = discord.NewVoiceClient(conn)
	return err
}

func (p *player) GetManifest(context.Context) (*corewire.ModuleManifest, error) {
	manifest := new(corewire.ModuleManifest)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(manifestJSON, manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

func (p *player) GetStatus(context.Context) (*corewire.Status, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	state := corewire.Readiness_READINESS_NOT_READY
	if p.failure != nil {
		state = corewire.Readiness_READINESS_FAILED
	} else if p.ready && !p.draining {
		state = corewire.Readiness_READINESS_READY
	}
	return &corewire.Status{Readiness: state}, nil
}

func (p *player) OnStage(ctx context.Context, req *corewire.StageRequest) error {
	if req == nil {
		return errors.New("missing player stage")
	}
	switch req.Stage {
	case corewire.Stage_STAGE_INIT:
		return p.initialize(ctx, req.InitContext)
	case corewire.Stage_STAGE_START:
		p.mu.Lock()
		if !p.ready || p.started || p.draining {
			p.mu.Unlock()
			return errors.New("player cannot start in current state")
		}
		p.started = true
		p.done = make(chan struct{})
		p.wg.Add(1)
		p.mu.Unlock()
		go p.run()
		go func() { p.wg.Wait(); close(p.done) }()
		return nil
	case corewire.Stage_STAGE_DRAIN, corewire.Stage_STAGE_STOP:
		return p.close(ctx)
	default:
		return errors.New("unsupported player stage")
	}
}

func (p *player) initialize(ctx context.Context, init *corewire.InitContext) (err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ready || p.draining || p.core == nil || p.discord == nil || p.voice == nil {
		return errors.New("player initialization state is invalid")
	}
	defer func() {
		if err != nil {
			p.failure = err
		}
	}()
	value, err := p.core.GetConfig(ctx)
	if err != nil {
		return err
	}
	cfg, err := decodeConfig(value.Json, init)
	if err != nil {
		return err
	}
	scratch, err := openScratch(init.ScratchDirectory)
	if err != nil {
		return err
	}
	if err = validateEncoder(ctx, scratch.path, cfg.Limits); err != nil {
		return errors.Join(err, scratch.Close())
	}
	p.cfg, p.scratch = cfg, scratch
	p.downloads = newAttachmentDownloader(cfg.Limits)
	p.queue = make(chan attachmentRequest, cfg.Limits.QueueEntries)
	p.slots = make(chan struct{}, cfg.Limits.QueueEntries)
	p.ready = true
	return nil
}

// START never waits for these RUNNING-only lookups: the authenticated host
// activation gate opens only after START returns. No media work is admitted
// until every configured channel has an actual, matching guild and type.
func (p *player) run() {
	defer p.wg.Done()
	ctx, cancel := context.WithTimeout(p.lifetime, p.cfg.Limits.operationTimeout)
	err := p.validateChannels(ctx)
	cancel()
	if err != nil {
		p.fail(err)
		return
	}
	p.mu.Lock()
	if p.draining {
		p.mu.Unlock()
		return
	}
	p.validated = true
	for range p.cfg.Limits.Workers {
		p.wg.Add(1)
		go p.worker()
	}
	p.mu.Unlock()
}

func (p *player) validateChannels(ctx context.Context) error {
	for _, target := range p.cfg.Targets {
		voice, err := p.discord.Channel(ctx, target.VoiceChannelID)
		if err != nil {
			return err
		}
		if voice == nil || voice.ID != target.VoiceChannelID || voice.GuildID != target.GuildID || voice.Type != discordgo.ChannelTypeGuildVoice {
			return errors.New("configured voice channel has an invalid actual guild or type")
		}
		for _, id := range target.TextChannelIDs {
			channel, err := p.discord.Channel(ctx, id)
			if err != nil {
				return err
			}
			if channel == nil || channel.ID != id || channel.GuildID != target.GuildID || channel.Type != discordgo.ChannelTypeGuildText {
				return errors.New("configured text channel has an invalid actual guild or type")
			}
		}
	}
	return nil
}

func (p *player) fail(err error) {
	p.mu.Lock()
	p.failure = errors.Join(p.failure, err)
	p.ready = false
	p.mu.Unlock()
	p.cancel()
}

func (p *player) OnEvent(ctx context.Context, envelope *corewire.EventEnvelope) error {
	decoded, err := discord.DecodeEvent(envelope)
	if err != nil {
		return err
	}
	event, ok := decoded.(*discordwire.MessageCreateEvent)
	if !ok {
		return errors.New("player received an undeclared event")
	}
	message := event.GetMessage().GetValue()
	if message == nil {
		return nil
	}
	author := message.GetAuthor().GetValue()
	if author == nil || author.GetBot().GetValue() || author.GetId().GetValue() == "" {
		return nil
	}
	guild, channel := message.GetGuildId().GetValue(), message.GetChannelId().GetValue()
	if guild == "" || channel == "" {
		return nil
	} // DM is never mapped to a default guild.
	var destination string
	for _, target := range p.cfg.Targets {
		if target.GuildID != guild {
			continue
		}
		for _, id := range target.TextChannelIDs {
			if id == channel {
				destination = target.VoiceChannelID
			}
		}
	}
	if destination == "" {
		return nil
	}
	p.mu.Lock()
	failed, available := p.failure != nil, p.started && p.validated && !p.draining
	p.mu.Unlock()
	if failed {
		return errors.New("player background operation failed")
	}
	if !available {
		return p.reply(ctx, channel, "Audio playback is not accepting work.")
	}
	var requests []attachmentRequest
	for _, item := range message.GetAttachments().GetValue().GetValues() {
		a := item.GetValue()
		if a == nil || !isAudioFile(a.GetFilename().GetValue()) {
			continue
		}
		if len(a.GetFilename().GetValue()) > 512 || len(a.GetUrl().GetValue()) > 8192 || a.GetSize().GetValue() < 0 || a.GetSize().GetValue() > p.cfg.Limits.MaxDownloadBytes {
			return p.reply(ctx, channel, "Attachment metadata exceeds the configured limits; this batch was not accepted.")
		}
		if len(requests) == p.cfg.Limits.QueueEntries {
			return p.reply(ctx, channel, "Attachment batch exceeds the configured queue limit.")
		}
		requests = append(requests, attachmentRequest{guild: guild, channel: channel, voice: destination, attachment: attachment{URL: a.GetUrl().GetValue(), Filename: a.GetFilename().GetValue(), Size: a.GetSize().GetValue()}})
	}
	if len(requests) == 0 {
		return nil
	}
	reserved := 0
	for range requests {
		select {
		case p.slots <- struct{}{}:
			reserved++
		default:
			for range reserved {
				<-p.slots
			}
			return p.reply(ctx, channel, "Audio queue is full; this batch was not accepted.")
		}
	}
	p.mu.Lock()
	if p.draining || p.failure != nil {
		p.mu.Unlock()
		for range requests {
			<-p.slots
		}
		return p.reply(ctx, channel, "Audio playback is draining.")
	}
	for _, request := range requests {
		p.queue <- request
	}
	p.mu.Unlock()
	return p.reply(ctx, channel, fmt.Sprintf("Accepted %d audio attachment(s). Playback completion will be reported separately.", len(requests)))
}

func (p *player) reply(ctx context.Context, channel, content string) error {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Limits.operationTimeout)
	defer cancel()
	_, err := p.discord.ChannelMessageSendComplex(ctx, channel, &discord.MessageSendView{Content: content, AllowedMentions: &discordgo.MessageAllowedMentions{Parse: []discordgo.AllowedMentionType{}}})
	return err
}

func (p *player) worker() {
	defer p.wg.Done()
	for {
		select {
		case <-p.lifetime.Done():
			return
		case request := <-p.queue:
			if p.lifetime.Err() != nil {
				<-p.slots
				return
			}
			err := p.play(request)
			<-p.slots
			if p.lifetime.Err() != nil {
				return
			}
			text := "Playback completed: the runtime confirmed the terminal COMPLETED state. This is not proof of audible delivery."
			if err != nil {
				text = "Audio preparation or playback failed; no completion was recorded."
			}
			if reportErr := p.reply(p.lifetime, request.channel, text); reportErr != nil {
				p.fail(errors.Join(err, reportErr))
				return
			}
		}
	}
}

func (p *player) close(ctx context.Context) error {
	p.mu.Lock()
	p.draining, p.ready = true, false
	if deadline, ok := ctx.Deadline(); ok && (p.cleanupDeadline.IsZero() || deadline.Before(p.cleanupDeadline)) {
		p.cleanupDeadline = deadline
	}
	done, scratch, downloads := p.done, p.scratch, p.downloads
	p.mu.Unlock()
	p.cancel()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if downloads != nil {
		downloads.close()
	}
	var err error
	if scratch != nil {
		err = scratch.Close()
	}
	p.mu.Lock()
	err = errors.Join(err, p.cleanupError)
	p.scratch = nil
	for p.queue != nil {
		select {
		case <-p.queue:
			<-p.slots
		default:
			p.mu.Unlock()
			return err
		}
	}
	p.mu.Unlock()
	return err
}

func main() {
	lifetime, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	player := newPlayer(lifetime)
	module, err := core.NewModulePlugin(lifetime, player, player.bind, core.TransportLimits{MaxReceiveBytes: 32 * 1024 * 1024, MaxSendBytes: 4 * 1024 * 1024})
	if err != nil {
		_, _ = io.WriteString(os.Stderr, "player bootstrap failed\n")
		return
	}
	defer module.Close()
	plugin.Serve(module.ServeConfig())
	cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	if player.close(cleanup) != nil {
		_, _ = io.WriteString(os.Stderr, "player cleanup failed\n")
	}
}
