package discordbackend

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	discordhttp "github.com/thirdscam/chatanium/internal/backend/discord/http"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
)

// ReconcileCommand is a trusted operator API, never a module RPC. It confirms an
// existing retained claim against the exact observed remote key and command ID;
// it cannot silently acquire an unregistered command or mutate Discord.
func (b *Backend) ReconcileCommand(ctx context.Context, module runtime.ModuleID, guild string, key CommandKey, commandID string) error {
	if module == "" || !snowflake(commandID) || (guild != "" && !snowflake(guild)) || key.Type < 1 || key.Type > 3 || key.Name == "" {
		return invalid("COMMAND_RECONCILIATION_INVALID")
	}
	bounded, cancel := context.WithTimeout(ctx, b.config.HTTP.RequestDeadline)
	defer cancel()
	stop := context.AfterFunc(b.life, cancel)
	defer stop()
	s := b.ownership
	select {
	case s.commands <- struct{}{}:
	case <-bounded.Done():
		return bounded.Err()
	}
	defer func() { <-s.commands }()
	var owner, state string
	e := s.db.QueryRowContext(bounded, "SELECT module,state FROM commands WHERE application=? AND guild=? AND type=? AND name=?", b.config.ApplicationID, guild, key.Type, key.Name).Scan(&owner, &state)
	if e == sql.ErrNoRows || owner != string(module) || state != "UNKNOWN" {
		return denied("COMMAND_RECONCILIATION_NOT_OWNED")
	}
	if e != nil {
		return unavailable("DISCORD_OWNERSHIP_READ_FAILED")
	}
	path := "/api/v10/applications/" + b.config.ApplicationID
	if guild != "" {
		path += "/guilds/" + guild
	}
	path += "/commands/" + commandID
	response, e := b.transport.Do(bounded, discordhttp.Request{Owner: "discord-operator", Method: "GET", Path: path, Bucket: "GET /applications/{application}/commands/{command}", Authorization: "Bot " + strings.TrimPrefix(b.config.BotToken, "Bot "), MaxBodyBytes: b.config.RequestMaxBytes})
	if e != nil {
		return externalError(e, "DISCORD_RECONCILIATION_FAILED", response.Dispatched)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return discordHTTPError(response.StatusCode, response.Body)
	}
	var actual struct {
		ID            string `json:"id"`
		ApplicationID string `json:"application_id"`
		GuildID       string `json:"guild_id"`
		Type          int32  `json:"type"`
		Name          string `json:"name"`
	}
	if json.Unmarshal(response.Body, &actual) != nil || actual.ID != commandID || actual.ApplicationID != b.config.ApplicationID || actual.GuildID != guild || actual.Type != key.Type || actual.Name != key.Name {
		return denied("COMMAND_RECONCILIATION_MISMATCH")
	}
	tx, e := s.db.BeginTx(bounded, nil)
	if e != nil {
		return unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(bounded, "DELETE FROM commands WHERE application=? AND guild=? AND command_id=? AND module=? AND NOT(type=? AND name=?)", b.config.ApplicationID, guild, commandID, string(module), key.Type, key.Name); e != nil {
		return unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
	}
	if _, e = tx.ExecContext(bounded, "UPDATE commands SET command_id=?,state='CONFIRMED' WHERE application=? AND guild=? AND type=? AND name=? AND module=?", commandID, b.config.ApplicationID, guild, key.Type, key.Name, string(module)); e != nil {
		return unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
	}
	if e = tx.Commit(); e != nil {
		return unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
	}
	return nil
}
