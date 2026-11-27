package runtime

import (
	"context"
	"testing"

	"github.com/thirdscam/chatanium/internal/discordacl"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/anypb"
)

func discordACLFixture(t *testing.T) (*Manager, *Instance, *Instance) {
	t.Helper()
	m := regressionManager()
	m.backends[discordBackend] = BackendRegistration{ID: discordBackend, Major: 1, ValidateSelector: func(*wire.ResourceSelector) error { return nil }}
	m.operations[operationKey(discordBackend, "write")] = OperationPolicy{Backend: discordBackend, Operation: "write", Capability: "write", Class: FiniteOperation}
	m.operations[operationKey(discordBackend, "ungranted")] = OperationPolicy{Backend: discordBackend, Operation: "ungranted", Capability: "ungranted", Class: FiniteOperation}
	m.operations[operationKey(discordBackend, "global")] = OperationPolicy{Backend: discordBackend, Operation: "global", Capability: "global", Class: FiniteOperation, ResourceFree: true}
	m.events[operationKey(discordBackend, "changed")] = m.events[operationKey(regressionBackend, "changed")]
	makeInstance := func(id ModuleID) *Instance {
		i := regressionInstance(t, m, id)
		all := &wire.ResourceScope{SelectorKind: &wire.ResourceScope_AllResources{AllResources: true}}
		i.grants.Backends = append(i.grants.Backends, &wire.BackendGrant{BackendId: discordBackend, ProtocolMajor: 1, Capabilities: []*wire.CapabilityGrant{
			{Name: "write", ResourceScopes: []*wire.ResourceScope{all}},
			{Name: "global", ResourceScopes: []*wire.ResourceScope{all}},
		}})
		return i
	}
	a, b := makeInstance("managed"), makeInstance("legacy")
	if err := m.setInitialDiscordACL(map[ModuleID]discordacl.Policy{a.principal.ModuleID: {}}); err != nil {
		t.Fatal(err)
	}
	a.discordACL = m.discordACL[a.principal.ModuleID]
	return m, a, b
}

func TestLiveDiscordACLChangesEventQueueAndRPCs(t *testing.T) {
	m, managed, legacy := discordACLFixture(t)
	ctx := context.Background()
	first := discordacl.Scope{GuildID: "10", ChannelID: "100"}
	second := discordacl.Scope{GuildID: "10", ChannelID: "101"}
	foreign := discordacl.Scope{GuildID: "20", ChannelID: "200"}
	update := func(scopes ...discordacl.Scope) {
		t.Helper()
		if err := m.SetDiscordACL(ctx, string(managed.principal.ModuleID), discordacl.Policy{Scopes: scopes}); err != nil {
			t.Fatal(err)
		}
	}
	scopeFor := func(s discordacl.Scope) *wire.ResourceScope { return regressionScope("guild_id", s.GuildID, "channel_id", s.ChannelID) }
	event := func(i *Instance, primary discordacl.Scope, nested ...discordacl.Scope) {
		t.Helper()
		e := regressionEvent(t, primary.ChannelID)
		e.BackendID = discordBackend
		e.Scope = scopeFor(primary)
		e.DiscordScopes = append([]discordacl.Scope{primary}, nested...)
		e.Recipient = func(p InstancePrincipal) bool { return p == i.principal }
		if err := m.Dispatcher().Admit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	authorize := func(i *Instance, op string, targets ...*wire.ResourceScope) (*Admission, error) {
		t.Helper()
		rpc, finish, err := i.beginRPC(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(finish)
		if _, err = (&Authorizer{instance: i}).Authorize(rpc, AccessRequest{Backend: discordBackend, Operation: op, Scopes: targets}); err != nil {
			finish()
			return nil, err
		}
		return AdmissionFromContext(rpc)
	}

	event(managed, first)
	if got := managed.Snapshot().RetainedEvents; got != 0 {
		t.Fatalf("explicit deny retained %d events", got)
	}
	_, err := authorize(managed, "write", scopeFor(first))
	regressionError(t, err, codes.PermissionDenied, "RESOURCE_SCOPE_DENIED")
	event(legacy, foreign)
	update(first, second)
	event(managed, first, foreign)
	event(managed, first, second)
	event(managed, second)
	if got := managed.Snapshot().RetainedEvents; got != 2 {
		t.Fatalf("want exactly two authorized events, got %d", got)
	}
	active, err := authorize(managed, "write", scopeFor(first))
	if err != nil {
		t.Fatal(err)
	}
	_, err = authorize(managed, "write", scopeFor(first), scopeFor(foreign))
	regressionError(t, err, codes.PermissionDenied, "RESOURCE_SCOPE_DENIED")
	_, err = authorize(managed, "ungranted", scopeFor(first))
	regressionError(t, err, codes.PermissionDenied, "REQUIRED_CAPABILITY_DENIED")
	_, err = authorize(managed, "global", resourceFreeScope())
	regressionError(t, err, codes.PermissionDenied, "RESOURCE_SCOPE_DENIED")

	update(second)
	if active.Context().Err() == nil {
		t.Fatal("revoked admission still active after acknowledgement")
	}
	queued := regressionQueuedEvents(t, managed)
	s := managed.Snapshot()
	if len(queued) != 1 || queued[0].IngressSequence != 5 || s.RetainedEvents != 1 || s.RetainedBytes != int64(len(managed.queue[0].raw)) {
		t.Fatalf("revocation did not keep exactly the allowed event and its reservation: %v; %+v", queued, s)
	}
	if i, _ := m.Instance(managed.principal.ModuleID); i != managed || s.State != Running {
		t.Fatal("replacing the policy restarted or failed the module")
	}
	_, err = authorize(managed, "write", scopeFor(first))
	regressionError(t, err, codes.PermissionDenied, "RESOURCE_SCOPE_DENIED")
	if _, err = authorize(managed, "write", scopeFor(second)); err != nil {
		t.Fatal(err)
	}
	if _, err = authorize(legacy, "write", scopeFor(foreign)); err != nil || len(regressionQueuedEvents(t, legacy)) != 1 {
		t.Fatalf("updating one module affected another: %v", err)
	}
}

func TestDiscordACLRevocationDuringProjectionDoesNotFailModule(t *testing.T) {
	m, managed, _ := discordACLFixture(t)
	ctx := context.Background()
	target := discordacl.Scope{GuildID: "10", ChannelID: "20"}
	if err := m.SetDiscordACL(ctx, "managed", discordacl.Policy{Scopes: []discordacl.Scope{target}}); err != nil {
		t.Fatal(err)
	}
	opened, finish := make(chan struct{}), make(chan struct{})
	e := regressionEvent(t, "revoked")
	e.BackendID = discordBackend
	e.Scope = regressionScope("guild_id", "10", "channel_id", "20")
	e.DiscordScopes = []discordacl.Scope{target}
	e.Recipient = func(p InstancePrincipal) bool { return p == managed.principal }
	e.Project = func(context.Context, InstancePrincipal) (*anypb.Any, error) {
		close(opened)
		<-finish
		return nil, invalidConfig()
	}
	result := make(chan error, 1)
	go func() { result <- m.Dispatcher().Admit(ctx, e) }()
	regressionWait(t, opened)
	err := m.SetDiscordACL(ctx, "managed", discordacl.Policy{})
	close(finish)
	if err != nil {
		t.Fatal(err)
	}
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	if s := managed.Snapshot(); s.State != Running || s.RetainedEvents != 0 {
		t.Fatalf("revoked projection altered module health or budget: %+v", s)
	}
}

func TestDiscordACLRevocationWaitsForAdmittedCallback(t *testing.T) {
	m, managed, _ := discordACLFixture(t)
	target := discordacl.Scope{GuildID: "10", ChannelID: "20"}
	if err := m.SetDiscordACL(context.Background(), "managed", discordacl.Policy{Scopes: []discordacl.Scope{target}}); err != nil {
		t.Fatal(err)
	}
	managed.mu.Lock()
	managed.discordWork = queuedEvent{discord: true, discordScopes: []discordacl.Scope{target}}
	managed.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waiting := &regressionGateContext{Context: ctx, waiting: make(chan struct{})}
	result := make(chan error, 1)
	go func() { result <- m.SetDiscordACL(waiting, "managed", discordacl.Policy{}) }()
	regressionWait(t, waiting.waiting)
	cancel()
	regressionError(t, <-result, codes.Canceled, "context canceled")

	managed.mu.Lock()
	allowed := managed.discordACL.Allows(target)
	waiters := managed.discordACLWaiters
	managed.discordWork = queuedEvent{}
	managed.signalLocked()
	managed.mu.Unlock()
	if !allowed || waiters != 0 {
		t.Fatal("unacknowledged replacement changed policy or left delivery paused")
	}
	if err := m.SetDiscordACL(context.Background(), "managed", discordacl.Policy{}); err != nil {
		t.Fatal(err)
	}
}
