package discordv2

import (
	"context"

	"github.com/bwmarrin/discordgo"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Client uses the authenticated reverse helper connection. It owns no Discord
// session, credential resolver, upload store or retry policy. File inputs must
// already have been uploaded explicitly with core.FileClient.
//
// Use the callback context for event followups: core.HelperContext forwards only
// its still-active host-issued work reference, never arbitrary caller metadata.
type Client struct {
	helper    wire.HelperClient
	ownership wire.BackendOwnershipClient
}

// NewClient binds all Discord operations and ownership helpers to one existing
// instance-scoped connection. It does not dial, upload, register or grant access.
func NewClient(conn grpc.ClientConnInterface) (*Client, error) {
	if conn == nil {
		return nil, clientInvalid()
	}
	return &Client{helper: wire.NewHelperClient(conn), ownership: wire.NewBackendOwnershipClient(conn)}, nil
}

// RequestOption is deliberately closed to the two fixed REST metadata fields.
// Context is always the first method argument, never an option. Applying an
// option to an unsupported operation is rejected by the backend, not dropped.
type RequestOption struct {
	auditLogReason *string
	locale         *string
}

func WithAuditLogReason(reason string) RequestOption {
	return RequestOption{auditLogReason: &reason}
}

func WithLocale(locale discordgo.Locale) RequestOption {
	value := string(locale)
	return RequestOption{locale: &value}
}

func clientOptions(options []RequestOption) *wire.RequestOptions {
	if len(options) == 0 {
		return nil
	}
	out := &wire.RequestOptions{}
	for _, option := range options {
		if option.auditLogReason != nil {
			out.AuditLogReason = copyPointer(option.auditLogReason)
		}
		if option.locale != nil {
			out.Locale = copyPointer(option.locale)
		}
	}
	return out
}

func clientInvalid() error { return core.NewError(codes.InvalidArgument, core.ReasonInvalidArgument) }
func clientMissing() error { return core.NewError(codes.Internal, core.ReasonInternal) }
func clientContext(ctx context.Context) error {
	if ctx == nil {
		return clientInvalid()
	}
	if err := ctx.Err(); err != nil {
		return status.FromContextError(err).Err()
	}
	return nil
}

// RegisterInteractionRoutes atomically claims the exact complete batch. Route
// ownership persists across restarts; success neither registers commands nor
// bypasses backend scope/capability checks.
func (c *Client) RegisterInteractionRoutes(ctx context.Context, claims []*wire.InteractionRouteClaim) error {
	if err := clientContext(ctx); err != nil {
		return err
	}
	value, err := c.ownership.RegisterInteractionRoutes(core.HelperContext(ctx), &wire.RegisterInteractionRoutesRequest{Claims: claims})
	if err != nil {
		return err
	}
	if value == nil {
		return clientMissing()
	}
	return nil
}

// UnregisterInteractionRoutes atomically releases the owned exact batch.
func (c *Client) UnregisterInteractionRoutes(ctx context.Context, claims []*wire.InteractionRouteClaim) error {
	if err := clientContext(ctx); err != nil {
		return err
	}
	value, err := c.ownership.UnregisterInteractionRoutes(core.HelperContext(ctx), &wire.UnregisterInteractionRoutesRequest{Claims: claims})
	if err != nil {
		return err
	}
	if value == nil {
		return clientMissing()
	}
	return nil
}

// GetProvisionedCredentialRef requests only a named operator-provisioned binding.
// The returned reference is finite and instance-bound; no secret is resolved.
func (c *Client) GetProvisionedCredentialRef(ctx context.Context, bindingName string) (*corewire.CredentialRef, error) {
	if err := clientContext(ctx); err != nil {
		return nil, err
	}
	value, err := c.ownership.GetProvisionedCredentialRef(core.HelperContext(ctx), &wire.GetProvisionedCredentialRefRequest{BindingName: bindingName})
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, clientMissing()
	}
	if err := validateCredentialRef(value, newConversion("ProtoToStruct", "GetProvisionedCredentialRef"), ""); err != nil {
		return nil, err
	}
	return cloneCredential(value), nil
}

// interactionWebhookTarget validates the safe handle without resolving it or
// widening its purpose. The backend remains authoritative for the precise
// application/channel/message binding and for @original eligibility.
func interactionWebhookTarget(interaction *InteractionHandle) (string, *corewire.CredentialRef, error) {
	if interaction == nil || interaction.Value == nil || interaction.Value.AppID == "" || interaction.Credential == nil || interaction.Credential.BackendId != "discord" || interaction.Credential.Purpose != "discord.interaction" {
		return "", nil, clientInvalid()
	}
	if interaction.Value.Token != "" {
		return "", nil, newConversion("StructToProto", "Interaction").fail("CredentialBoundaryRequired", "Token", "raw interaction token is forbidden")
	}
	if err := validateCredentialRef(interaction.Credential, newConversion("StructToProto", "Interaction"), "Credential"); err != nil {
		return "", nil, err
	}
	return interaction.Value.AppID, interaction.Credential, nil
}
