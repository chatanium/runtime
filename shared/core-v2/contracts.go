// Package corev2 implements the backend-neutral FlexModule v2 module SDK.
// Authentication, actual grants, lifecycle admission and resource ownership are
// host responsibilities; none are inferred from RPC metadata by this package.
package corev2

import (
	"context"
	"time"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/grpc"
)

const (
	// ProtocolMajor is the application handshake and manifest major version.
	ProtocolMajor = 2
	// PluginKey is the only go-plugin service key in application protocol v2.
	PluginKey = "core-v2"
	// HelperBrokerID identifies the single authenticated reverse connection.
	HelperBrokerID uint32 = 1
	// WorkRefMetadata is a bounded active-delivery reference, never an identity.
	WorkRefMetadata        = "flexmodule-work-ref"
	CapabilityConfigRead   = "core.config.read"
	CapabilityUpload       = "core.upload"
	CapabilityPublicEgress = "core.network.public_egress"
)

// ModuleHooks is the complete module-facing lifecycle and event contract.
// Implementations must honor cancellation and return actual failures. START
// launches workers and returns without waiting for RUNNING-only helper calls.
// DRAIN must not wait for queued events that the host can still deliver.
type ModuleHooks interface {
	GetManifest(context.Context) (*wire.ModuleManifest, error)
	GetStatus(context.Context) (*wire.Status, error)
	OnStage(context.Context, *wire.StageRequest) error
	OnEvent(context.Context, *wire.EventEnvelope) error
}

// CoreClient returns only the authenticated instance's structured configuration.
// Configuration is an exact JSON object, not a flattened string map.
type CoreClient interface {
	GetConfig(context.Context) (*wire.JSONValue, error)
}

// CredentialBinding describes one secret's permitted use and finite lifetime.
// The owner is obtained from ctx, never from these caller-visible fields.
type CredentialBinding struct {
	BackendID     string
	Purpose       string
	ResourceScope *wire.ResourceSelector
	ExpiresAt     time.Time
}

// CredentialUse describes the exact operation binding expected by an adapter.
// It is constructed by trusted operation policy, not copied from the ref.
type CredentialUse struct {
	BackendID     string
	Purpose       string
	ResourceScope *wire.ResourceSelector
}

// CredentialEncoder exists only on the runtime side of the trust boundary.
// It stores the raw secret for the authenticated destination instance and returns
// a typed opaque ref; it must not log or embed the raw secret in diagnostics.
type CredentialEncoder interface {
	EncodeCredential(ctx context.Context, binding CredentialBinding, rawSecret string) (*wire.CredentialRef, error)
}

// CredentialResolver is host-only and is never exposed as a module RPC.
// It checks owner, purpose, resource, expiry and instance state before returning
// a secret for the immediate trusted adapter call.
type CredentialResolver interface {
	ResolveCredential(ctx context.Context, ref *wire.CredentialRef, expected CredentialUse) (string, error)
}

// HelperBinder installs core and selected backend clients before user INIT.
// The connection is owned by ModulePlugin. The callback must honor ctx and must
// not close or retain independent ownership of the connection. The supplied
// connection enforces HelperContext for all calls, including stream creation.
type HelperBinder func(ctx context.Context, conn grpc.ClientConnInterface) error

// HelperRegistrar installs concrete instance-bound helper services. Its closure
// captures the host's trusted principal and authorizer; no identity is accepted
// from module payloads or metadata. Registration must not perform blocking work.
// Services registered before manifest/grant negotiation must deny all access
// until P4 has bound the immutable actual grants to this authenticated instance.
type HelperRegistrar func(grpc.ServiceRegistrar) error

// HelperServerFactory constructs a per-instance server using ALL brokerOptions,
// including the broker's AutoMTLS credentials. The host adds its own finite RPC
// limits and principal-binding interceptors. It must return a fresh server with
// no services registered; the bridge invokes every supplied registrar before
// signaling readiness. Construction must not block or perform I/O. This is the
// P4 authentication integration boundary.
type HelperServerFactory func(brokerOptions []grpc.ServerOption) (*grpc.Server, error)

// TransportLimits are explicit finite transport limits. There are no unlimited
// defaults. JSON limits are separately required by NewCoreClient.
type TransportLimits struct {
	MaxReceiveBytes int
	MaxSendBytes    int
}

func (l TransportLimits) valid() bool { return l.MaxReceiveBytes > 0 && l.MaxSendBytes > 0 }
