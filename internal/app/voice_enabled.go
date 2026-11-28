//go:build voice && cgo

package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	discordbackend "github.com/thirdscam/chatanium/internal/backend/discord"
	"github.com/thirdscam/chatanium/internal/backend/discord/voicejobs"
)

const VoiceEnabled = true

func attachVoice(ctx context.Context, b *discordbackend.Backend, raw json.RawMessage, maxMessageBytes int) error {
	if len(raw) == 0 {
		return nil
	}
	var config voicejobs.Config
	if StrictJSON(raw, &config) != nil || config.Validate() != nil || config.MaxGRPCMessageBytes != maxMessageBytes {
		return errors.New("invalid finite voice configuration")
	}
	service, err := voicejobs.New(ctx, voicejobs.Options{Config: config, Session: b.HostSession(), ResolveChannel: b.ResolveVoiceChannel})
	if err != nil {
		return errors.New("voice backend initialization failed")
	}
	if b.AttachExtension(service) != nil {
		bounded, cancel := context.WithTimeout(context.Background(), time.Duration(config.CleanupTimeout))
		defer cancel()
		service.Close(bounded)
		return errors.New("voice backend attachment failed")
	}
	return nil
}
