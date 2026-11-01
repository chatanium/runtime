// Package discordbackend implements the host-owned Discord v2 backend.
package discordbackend

import (
	"context"
	"time"

	discordhttp "github.com/thirdscam/chatanium/internal/backend/discord/http"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
)

const BackendID = "discord"
const BackendMajor uint32 = 2

// ResourceTarget is a trusted planner declaration, never a caller assertion of
// ownership. Kind is a selector key (guild_id, channel_id, user_id, ...).
// GuildID/ChannelID/ApplicationID are expected relationships and are verified.
type ResourceTarget struct {
	Kind          string
	ID            string
	GuildID       string
	ChannelID     string
	ApplicationID string
	MessageID     string
}
type RouteKey struct {
	ApplicationID string
	Kind          int32
	CustomID      string
}
type CredentialUse struct {
	Ref      *corewire.CredentialRef
	Purpose  string
	Resource *corewire.ResourceSelector
	// ThreadDestination is only the explicit WebhookThreadExecute destination.
	// Resource remains the credential's immutable parent binding.
	ThreadDestination string
	// Apply inserts a resolved secret only into the fixed endpoint path/body slot.
	Apply           func(secret string) error
	InitialCallback bool
}
type CommandMutation struct {
	ApplicationID string
	GuildID       string
	CommandID     string
	Commands      []CommandKey
	Bulk          bool
	Delete        bool
}
type CommandKey struct {
	Type int32
	Name string
}

// MemberRoleReplacement is present only when the roles field is present.
// Replacement requires guild-wide authority because Discord has no atomic
// assignment-version precondition for the member PATCH.
type MemberRoleReplacement struct {
	GuildID string
	UserID  string
	RoleIDs []string
}

// RESTPlan is constructed only by fixed, typed, operation-specific code.
type RESTPlan struct {
	Request discordhttp.Request
	Targets []ResourceTarget
	// RequiredRoots are real mutation roots, never pruned as relationship-only
	// ancestors of nested resources.
	RequiredRoots          []ResourceTarget
	RoleReplacement        *MemberRoleReplacement
	credentialDestinations map[string]credentialDestination
	// FullList requires an actual all_resources grant; filtering cannot turn a
	// namespace-wide result into a correctly scoped response.
	FullList        bool
	ResourceFree    bool
	NoDispatch      bool
	RequireResponse bool
	Credentials     []CredentialUse
	Files           []*wire.FileAttachment
	Routes          []RouteKey
	Command         *CommandMutation
	// ValidateResult checks relationships that are only knowable from the result.
	ValidateResult func(context.Context, []byte, []*corewire.ResourceScope) error
}
type OperationContext struct {
	Context                context.Context
	Principal              runtime.InstancePrincipal
	Admission              *runtime.Admission
	Scopes                 []*corewire.ResourceScope
	credentialDestinations map[string]credentialDestination
	// invokingUser is authenticated interaction context, not a returned message
	// author's identity or a user supplied in helper request metadata.
	invokingUser string
}
type Helper struct {
	backend  *Backend
	services runtime.InstanceServices
}

type Secret struct {
	Value     string
	Purpose   string
	Resource  *corewire.ResourceSelector
	ExpiresAt time.Time
	ModuleID  runtime.ModuleID
}

// VoicePort is host-only. No module DTO or credential can access this port.
type VoicePort interface {
	OnBotVoiceState(context.Context, BotVoiceState)
	OnVoiceServer(context.Context, VoiceServer)
}
type BotVoiceState struct{ GuildID, ChannelID, UserID, SessionID string }
type VoiceServer struct{ GuildID, Endpoint, Token string }
