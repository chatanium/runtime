package discordbackend

import (
	"github.com/bwmarrin/discordgo"
	"github.com/thirdscam/chatanium/internal/backend/discord/discordhttp"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	"github.com/thirdscam/chatanium/internal/runtime/upload"
	"google.golang.org/grpc/codes"
	"net/http"
	"path/filepath"
	"time"
)

// Config is operator input. Secrets never originate in ModuleSpec.Config.
// All resource limits are required; zero never means unbounded.
type Config struct {
	BotToken      string
	ApplicationID string
	BotUserID     string
	// OwnershipDirectory is a separate operator-created, worker-owned private
	// directory (0700 on Unix, owner-only DACL on Windows).
	OwnershipDirectory string
	// PortableOwnership confines SQLite to the approved portable storage reservation.
	PortableOwnership      bool
	HTTP                   discordhttp.Config
	Client                 *http.Client
	Intents                discordgo.Intent
	GatewayFrameMaxBytes   int64
	GatewayDecodedMaxBytes int64
	CredentialTTL          time.Duration
	InteractionTTL         time.Duration
	NonceTTL               time.Duration
	NoncesPerInstance      int
	NoncesPerHost          int
	NonceChunksMax         int
	RoutesPerModule        int
	RoutesPerHost          int
	MaxRoutesPerRequest    int
	MaxFilesPerRequest     int
	FileMaxBytes           int64
	RequestMaxBytes        int64
	PresenceOwner          runtime.ModuleID
	Secrets                map[string]Secret
	Uploads                *upload.UploadStore
	// OnError runs on ingress callbacks too; it must not synchronously reenter
	// backend or SDK lifecycle APIs.
	OnError func(error)
}

func invalid(reason string) error { return localError(codes.InvalidArgument, reason) }
func denied(reason string) error {
	switch reason {
	case "COMMAND_OWNERSHIP_CONFLICT", "INTERACTION_ROUTE_OWNERSHIP_CONFLICT":
		return localError(codes.AlreadyExists, reason)
	case "COMMAND_NAMESPACE_NOT_EXCLUSIVE", "DISCORD_PRESENCE_OWNER_CONFLICT":
		return localError(codes.FailedPrecondition, reason)
	case "CREDENTIAL_REFERENCE_INVALID":
		reason = "REF_SCOPE_MISMATCH"
	}
	return localError(codes.PermissionDenied, reason)
}
func unavailable(reason string) error {
	switch reason {
	case "DISCORD_RESPONSE_INVALID", "DISCORD_EVENT_INVALID", "DISCORD_OWNERSHIP_READ_FAILED", "DISCORD_OWNERSHIP_WRITE_FAILED", "DISCORD_COMMAND_RESULT_INVALID":
		return localError(codes.Internal, reason)
	}
	return localError(codes.FailedPrecondition, reason)
}
func (c Config) validate() error {
	if c.GatewayFrameMaxBytes <= 0 || c.GatewayDecodedMaxBytes <= 0 {
		return invalid("DISCORD_CONFIGURATION_INVALID")
	}
	if c.BotToken == "" || !snowflake(c.ApplicationID) || !snowflake(c.BotUserID) || !filepath.IsAbs(c.OwnershipDirectory) || c.CredentialTTL <= 0 || c.InteractionTTL <= 0 || c.NonceTTL <= 0 || c.NoncesPerInstance <= 0 || c.NoncesPerHost < c.NoncesPerInstance || c.RoutesPerModule <= 0 || c.RoutesPerHost < c.RoutesPerModule || c.MaxRoutesPerRequest <= 0 || c.MaxFilesPerRequest <= 0 || c.MaxFilesPerRequest > 10 || c.FileMaxBytes <= 0 || c.RequestMaxBytes <= 0 || c.Uploads == nil || c.OnError == nil {
		return invalid("DISCORD_CONFIGURATION_INVALID")
	}
	// Discord interaction credentials expire fifteen minutes after creation.
	if c.InteractionTTL > 15*time.Minute {
		return invalid("DISCORD_CONFIGURATION_INVALID")
	}
	if c.NonceChunksMax <= 0 {
		return invalid("DISCORD_CONFIGURATION_INVALID")
	}
	for name, s := range c.Secrets {
		if name == "" || s.Value == "" || s.ModuleID == "" || s.Purpose != "discord.user.guilds.join" || !s.ExpiresAt.After(time.Now()) || validateSelector(s.Resource) != nil || s.Resource.ResourceIds["application_id"] != c.ApplicationID || s.Resource.ResourceIds["user_id"] == "" || s.Resource.ResourceIds["guild_id"] == "" {
			return invalid("DISCORD_SECRET_CONFIGURATION_INVALID")
		}
	}
	return nil
}
func snowflake(s string) bool {
	if len(s) == 0 || len(s) > 20 {
		return false
	}
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
		d := uint64(c - '0')
		if n > (^uint64(0)-d)/10 {
			return false
		}
		n = n*10 + d
	}
	return n != 0
}
