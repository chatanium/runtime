package discordbackend

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/bwmarrin/discordgo"
	discordhttp "github.com/thirdscam/chatanium/internal/backend/discord/http"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	discordv2 "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type instanceBinding struct {
	services runtime.InstanceServices
	grant    *corewire.BackendGrant
	active   bool
	ctx      context.Context
	cancel   context.CancelFunc
	workers  int
	changed  chan struct{}
}
type Backend struct {
	config           Config
	session          *discordgo.Session
	transport        *discordhttp.Transport
	ownership        *ownershipStore
	mu               sync.Mutex
	instances        map[runtime.InstanceID]*instanceBinding
	dispatcher       *runtime.Dispatcher
	voice            VoicePort
	extension        Extension
	sealed           bool
	vault            map[string]*vaultRecord
	nonces           map[string]*nonceRecord
	life             context.Context
	closeDone        chan struct{}
	closeErr         error
	cancel           context.CancelFunc
	stopParent       func() bool
	identityVerified bool
	closed           bool
}

// New's context is the host backend lifetime, never a startup or creation RPC.
func New(ctx context.Context, c Config) (*Backend, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	secrets := make(map[string]Secret, len(c.Secrets))
	for name, secret := range c.Secrets {
		secret.Resource = copySelector(secret.Resource)
		secrets[name] = secret
	}
	c.Secrets = secrets
	tr, err := discordhttp.New(c.HTTP, c.Client)
	if err != nil {
		return nil, err
	}
	store, err := openOwnership(filepath.Join(c.OwnershipDirectory, "discord-ownership.sqlite"), c)
	if err != nil {
		tr.Close()
		return nil, err
	}
	s, err := discordgo.New("Bot " + strings.TrimPrefix(c.BotToken, "Bot "))
	if err != nil {
		store.Close()
		tr.Close()
		return nil, unavailable("DISCORD_SESSION_CONFIGURATION_INVALID")
	}
	s.Identify.Intents = c.Intents
	s.MaxRestRetries = 0
	s.ShouldRetryOnRateLimit = false
	s.ShouldReconnectOnError = false
	s.Debug = false
	s.LogLevel = -1
	// Bootstrap and all helper traffic use a copied trusted client. Redirects may
	// neither replay mutation bodies nor export authentication to another origin.
	client := http.Client{}
	if c.Client != nil {
		client = *c.Client
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = c.HTTP.RequestDeadline
	s.Client = &client
	life, cancel := context.WithCancel(ctx)
	b := &Backend{config: c, session: s, transport: tr, ownership: store, instances: make(map[runtime.InstanceID]*instanceBinding), vault: make(map[string]*vaultRecord), nonces: make(map[string]*nonceRecord), life: life, cancel: cancel}
	b.closeDone = make(chan struct{})
	if err = s.ConfigureGatewayIngress(c.GatewayFrameMaxBytes, c.GatewayDecodedMaxBytes, b.gatewayIngressFailed); err != nil {
		cancel()
		store.Close()
		tr.Close()
		return nil, invalid("DISCORD_CONFIGURATION_INVALID")
	}
	s.SetDispatchObserver(b.observe)
	s.AddHandler(func(_ *discordgo.Session, _ *discordgo.Disconnect) {
		b.mu.Lock()
		closed, dispatcher := b.closed, b.dispatcher
		b.mu.Unlock()
		if !closed && dispatcher != nil {
			if e := dispatcher.FailBackend(b.life, BackendID, "DISCORD_GATEWAY_STATE_FAILED"); e != nil {
				b.config.OnError(e)
			}
			b.config.OnError(unavailable("DISCORD_GATEWAY_STATE_FAILED"))
		}
	})
	b.mu.Lock()
	b.stopParent = context.AfterFunc(ctx, func() {
		if e := b.Close(); e != nil {
			b.config.OnError(unavailable("DISCORD_BACKEND_CLOSE_FAILED"))
		}
	})
	b.mu.Unlock()
	return b, nil
}

// AttachDispatcher is called once after NewManager and before Open or Launch.
func (b *Backend) AttachDispatcher(d *runtime.Dispatcher) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if d == nil || b.dispatcher != nil || b.closed {
		return invalid("DISCORD_DISPATCHER_INVALID")
	}
	b.dispatcher = d
	return nil
}
func (b *Backend) Open(ctx context.Context) error {
	b.mu.Lock()
	ready := b.dispatcher != nil && !b.closed
	b.mu.Unlock()
	if !ready {
		return unavailable("DISCORD_DISPATCHER_NOT_ATTACHED")
	}
	bounded, cancel := context.WithTimeout(ctx, b.config.HTTP.RequestDeadline)
	defer cancel()
	stop := context.AfterFunc(b.life, cancel)
	defer stop()
	if e := b.session.OpenContext(bounded); e != nil {
		return externalError(e, "DISCORD_GATEWAY_OPEN_FAILED", true)
	}
	b.mu.Lock()
	verified := b.identityVerified
	b.mu.Unlock()
	if !verified {
		_ = b.session.Close()
		return unavailable("DISCORD_GATEWAY_IDENTITY_MISMATCH")
	}
	return nil
}
func (b *Backend) Close() error {
	b.mu.Lock()
	if b.closed {
		done := b.closeDone
		b.mu.Unlock()
		<-done
		b.mu.Lock()
		e := b.closeErr
		b.mu.Unlock()
		return e
	}
	b.closed = true
	if b.stopParent != nil {
		b.stopParent()
	}
	b.cancel()
	for _, i := range b.instances {
		i.cancel()
	}
	for _, r := range b.vault {
		r.secret = ""
		if r.timer != nil {
			r.timer.Stop()
		}
	}
	b.vault = make(map[string]*vaultRecord)
	for id, r := range b.nonces {
		r.timer.Stop()
		delete(b.nonces, id)
	}
	b.mu.Unlock()
	var extensionError error
	if b.extension != nil {
		bounded, cancel := context.WithTimeout(context.Background(), b.config.HTTP.RequestDeadline)
		extensionError = b.extension.Close(bounded)
		cancel()
	}
	// Cancellation makes every in-flight projection/admission finite. Detaching
	// joins the ordered observer before the Session and ownership store close.
	b.session.SetDispatchObserver(nil)
	e1 := b.session.Close()
	e2 := b.transport.Close()
	b.mu.Lock()
	for {
		var pending <-chan struct{}
		for _, i := range b.instances {
			if i.workers != 0 {
				pending = i.changed
				break
			}
		}
		if pending == nil {
			break
		}
		b.mu.Unlock()
		<-pending
		b.mu.Lock()
	}
	b.mu.Unlock()
	e3 := b.ownership.Close()
	result := extensionError
	if result == nil && e1 != nil {
		result = unavailable("DISCORD_SESSION_CLOSE_FAILED")
	}
	if result == nil {
		result = e2
	}
	if result == nil {
		result = e3
	}
	b.mu.Lock()
	b.closeErr = result
	close(b.closeDone)
	b.mu.Unlock()
	return result
}
func (b *Backend) Registration() runtime.BackendRegistration {
	b.mu.Lock()
	b.sealed = true
	b.mu.Unlock()
	r := runtime.BackendRegistration{ID: BackendID, Major: BackendMajor, Adapter: b, ValidateSelector: validateSelector, Register: b.register, ValidateConstraints: b.validateConstraints, ValidateConstraintsSubset: b.validateConstraintsSubset}
	for _, op := range discordv2.CanonicalOperations() {
		// Only finite REST follow-ups may use the runtime's exact live event
		// work reference during drain; lifecycle/resource admission stays closed.
		r.Operations = append(r.Operations, runtime.OperationPolicy{Backend: BackendID, Operation: op.Name, Capability: op.Capability, Class: runtime.FiniteOperation, InitSafe: strings.HasPrefix(op.Name, "ApplicationCommand"), DrainSafe: op.Transport == "rest", ResourceFree: resourceFreeOperation(op.Name)})
	}
	for _, e := range discordv2.EventRegistry() {
		r.Operations = append(r.Operations, runtime.OperationPolicy{Backend: BackendID, Operation: e.Capability, Capability: e.Capability, Class: runtime.FiniteOperation, ResourceFree: eventResourceFree(e.Name)})
		r.Events = append(r.Events, runtime.EventPolicy{EventType: e.Name, Operation: e.Capability, PayloadTypeURL: e.TypeURL})
	}
	for _, x := range discordv2.BackendOwnershipOperations() {
		p := runtime.OperationPolicy{Backend: BackendID, Operation: x.Name, Capability: x.Capability, InitSafe: true, Class: runtime.FiniteOperation}
		if x.Name == "UnregisterInteractionRoutes" {
			p.Class = runtime.OwnerCleanupOperation
		}
		r.Operations = append(r.Operations, p)
	}
	if b.extension != nil {
		r.Operations = append(r.Operations, b.extension.Operations()...)
	}
	return r
}
func (b *Backend) register(s runtime.InstanceServices) (core.HelperRegistrar, error) {
	if s.Authorizer == nil || s.Credentials == nil {
		return nil, invalid("DISCORD_INSTANCE_SERVICES_INVALID")
	}
	life, cancel := context.WithCancel(b.life)
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		cancel()
		return nil, unavailable("DISCORD_BACKEND_CLOSED")
	}
	if _, ok := b.instances[s.Principal.InstanceID]; ok {
		b.mu.Unlock()
		cancel()
		return nil, invalid("DISCORD_INSTANCE_DUPLICATE")
	}
	b.instances[s.Principal.InstanceID] = &instanceBinding{services: s, ctx: life, cancel: cancel, changed: make(chan struct{})}
	b.mu.Unlock()
	var extra core.HelperRegistrar
	if b.extension != nil {
		var e error
		extra, e = b.extension.Register(s)
		if e != nil {
			return nil, e
		}
	}
	return func(server grpc.ServiceRegistrar) error {
		h := &Helper{backend: b, services: s}
		wire.RegisterHelperServer(server, h)
		wire.RegisterBackendOwnershipServer(server, h)
		if extra != nil {
			return extra(server)
		}
		return nil
	}, nil
}
func (b *Backend) Prepare(ctx context.Context, p runtime.InstancePrincipal, in runtime.BackendPreparation) (*runtime.BackendBinding, error) {
	if in.Approved == nil || in.Approved.BackendId != BackendID || in.Approved.ProtocolMajor != BackendMajor {
		return nil, denied("REQUIRED_BACKEND_DENIED")
	}
	b.mu.Lock()
	ready := b.identityVerified && !b.closed
	b.mu.Unlock()
	if !ready {
		return nil, unavailable("DISCORD_GATEWAY_NOT_READY")
	}
	actual := proto.Clone(in.Approved).(*corewire.BackendGrant)
	actual.Capabilities = nil
	required := map[string]bool{}
	if in.Requirement != nil {
		for _, c := range in.Requirement.RequiredCapabilities {
			if c != nil {
				required[c.Name] = true
			}
		}
	}
	for _, g := range in.Approved.Capabilities {
		if g == nil {
			return nil, invalid("DISCORD_GRANT_INVALID")
		}
		reason := ""
		if strings.HasPrefix(g.Name, "discord.voice.") {
			continue
		}
		if g.Name == "discord.gateway.UpdateStatusComplex" && p.ModuleID != b.config.PresenceOwner {
			reason = "DISCORD_PRESENCE_OWNER_CONFLICT"
		}
		if (g.Name == "discord.gateway.RequestGuildMembers" || g.Name == "discord.gateway.RequestGuildMembersList") && b.config.Intents&discordgo.IntentGuildMembers == 0 {
			reason = "BACKEND_RECONFIGURATION_REQUIRED"
		}
		if strings.HasPrefix(g.Name, "discord.event.") {
			if e, ok := discordv2.LookupEvent(strings.TrimPrefix(g.Name, "discord.event.")); ok && !intentsAvailable(b.config.Intents, e) {
				reason = "BACKEND_RECONFIGURATION_REQUIRED"
			}
		}
		if reason != "" {
			if required[g.Name] {
				return nil, unavailable(reason)
			}
			continue
		}
		actual.Capabilities = append(actual.Capabilities, proto.Clone(g).(*corewire.CapabilityGrant))
	}
	voiceGrants, e := b.extensionGrants(ctx, p, in)
	if e != nil {
		return nil, e
	}
	for _, g := range voiceGrants {
		actual.Capabilities = append(actual.Capabilities, proto.Clone(g).(*corewire.CapabilityGrant))
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	i := b.instances[p.InstanceID]
	if i == nil || i.services.Principal != p {
		return nil, unavailable("DISCORD_INSTANCE_NOT_REGISTERED")
	}
	i.grant = actual
	return &runtime.BackendBinding{Grant: proto.Clone(i.grant).(*corewire.BackendGrant)}, nil
}
func (b *Backend) Activate(ctx context.Context, p runtime.InstancePrincipal) error {
	if b.extension != nil {
		if e := b.extension.Activate(ctx, p); e != nil {
			return e
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	i := b.instances[p.InstanceID]
	if i == nil || i.services.Principal != p || i.grant == nil {
		return unavailable("DISCORD_INSTANCE_NOT_PREPARED")
	}
	i.active = true
	return nil
}
func (b *Backend) Drain(ctx context.Context, p runtime.InstancePrincipal) error {
	b.mu.Lock()
	if i := b.instances[p.InstanceID]; i != nil && i.services.Principal == p {
		i.active = false
	}
	b.mu.Unlock()
	if b.extension != nil {
		return b.extension.Drain(ctx, p)
	}
	return nil
}
func (b *Backend) Cleanup(ctx context.Context, p runtime.InstancePrincipal) error {
	b.mu.Lock()
	i := b.instances[p.InstanceID]
	if i != nil && i.services.Principal == p {
		i.active = false
		i.cancel()
	}
	b.mu.Unlock()
	var extensionError error
	if b.extension != nil {
		extensionError = b.extension.Cleanup(ctx, p)
	}
	b.mu.Lock()
	if i != nil && i.services.Principal == p {
		for i.workers != 0 {
			changed := i.changed
			b.mu.Unlock()
			select {
			case <-changed:
			case <-ctx.Done():
				return ctx.Err()
			}
			b.mu.Lock()
		}
		delete(b.instances, p.InstanceID)
	}
	for id, r := range b.vault {
		if r.owner == p {
			r.secret = ""
			if r.timer != nil {
				r.timer.Stop()
			}
			delete(b.vault, id)
		}
	}
	for id, r := range b.nonces {
		if r.owner == p {
			r.timer.Stop()
			delete(b.nonces, id)
		}
	}
	b.mu.Unlock()
	return extensionError
}
func (b *Backend) beginWork(p runtime.InstancePrincipal) (context.Context, func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	i := b.instances[p.InstanceID]
	if b.closed || i == nil || i.services.Principal != p || i.ctx.Err() != nil {
		return nil, nil, unavailable("DISCORD_INSTANCE_NOT_RUNNING")
	}
	i.workers++
	var once sync.Once
	return i.ctx, func() {
		once.Do(func() { b.mu.Lock(); i.workers--; close(i.changed); i.changed = make(chan struct{}); b.mu.Unlock() })
	}, nil
}
func randomOpaque() (string, error) {
	var v [32]byte
	if _, err := rand.Read(v[:]); err != nil {
		return "", unavailable("DISCORD_ENTROPY_UNAVAILABLE")
	}
	return hex.EncodeToString(v[:]), nil
}
func resourceFreeOperation(n string) bool {
	switch n {
	case "Gateway", "GatewayBot", "VoiceRegions", "UpdateStatusComplex", "UserUpdate", "UserGuilds":
		return true
	}
	return false
}
func eventResourceFree(n string) bool { return n == "READY" || n == "USER_UPDATE" }
func (b *Backend) AttachVoicePort(v VoicePort) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if v == nil || b.voice != nil {
		return invalid("DISCORD_VOICE_PORT_INVALID")
	}
	b.voice = v
	return nil
}
func (b *Backend) SendVoiceState(ctx context.Context, guildID, channelID string, mute, deaf bool) error {
	if !snowflake(guildID) || (channelID != "" && !snowflake(channelID)) {
		return invalid("DISCORD_VOICE_TARGET_INVALID")
	}
	bounded, cancel := context.WithTimeout(ctx, b.config.HTTP.RequestDeadline)
	defer cancel()
	stop := context.AfterFunc(b.life, cancel)
	defer stop()
	if e := b.session.ChannelVoiceJoinManualContext(bounded, guildID, channelID, mute, deaf); e != nil {
		return externalError(e, "DISCORD_GATEWAY_WRITE_FAILED", true)
	}
	return nil
}
