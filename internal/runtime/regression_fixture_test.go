package runtime

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
)

const regressionBackend = "test-backend"

// These fixtures start at the authenticated/bound instance boundary. No host,
// plugin, backend adapter or lifecycle callback is substituted.
func regressionManager() *Manager {
	policy := OperationPolicy{Backend: regressionBackend, Operation: "write", Capability: "write", Class: FiniteOperation, DrainSafe: true}
	m := &Manager{
		config: Config{
			Defaults: Defaults{EventQueueEvents: 2, EventQueueBytes: 4096},
			Limits:   Limits{ControlRPCsPerInstance: 4, ControlMessageMaxBytes: 4096, CredentialRefsPerInstance: 4, CredentialRefMaxTTL: Duration(time.Hour)},
		},
		instances: make(map[ModuleID]*Instance), installed: make(map[ModuleID]struct{}),
		backends: map[string]BackendRegistration{regressionBackend: {
			ID: regressionBackend, Major: 1, Operations: []OperationPolicy{policy},
			ValidateSelector: func(s *wire.ResourceSelector) error {
				if s == nil || len(s.ResourceIds) == 0 {
					return invalidConfig()
				}
				for k, v := range s.ResourceIds {
					if (k != "group" && k != "item") || v == "" {
						return invalidConfig()
					}
				}
				return nil
			},
		}},
		operations: map[string]OperationPolicy{operationKey(regressionBackend, "write"): policy},
		events:     map[string]EventPolicy{operationKey(regressionBackend, "changed"): {EventType: "changed", Operation: "write", PayloadTypeURL: "type.googleapis.com/google.protobuf.StringValue"}},
	}
	m.credentials = &CredentialRegistry{manager: m}
	m.dispatcher = &Dispatcher{manager: m}
	return m
}

func regressionInstance(t *testing.T, m *Manager, id ModuleID) *Instance {
	t.Helper()
	startup, cancelStartup := context.WithCancel(context.Background())
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	i := &Instance{
		manager: m, principal: InstancePrincipal{ModuleID: id, InstanceID: InstanceID(string(id) + "-instance")},
		state: Running, bound: true, startup: startup, cancelStartup: cancelStartup,
		lifetime: lifetime, cancelLifetime: cancelLifetime, gate: make(chan struct{}), changed: make(chan struct{}),
		admissions: make(map[*Admission]struct{}), credentials: make(map[string]*credentialRecord),
		grants: &wire.Grants{Backends: []*wire.BackendGrant{{BackendId: regressionBackend, ProtocolMajor: 1, Capabilities: []*wire.CapabilityGrant{{Name: "write", ResourceScopes: []*wire.ResourceScope{regressionScope("group", "a"), regressionScope("group", "b")}}}}}},
	}
	m.instances[id] = i
	m.installed[id] = struct{}{}
	t.Cleanup(func() {
		i.mu.Lock()
		revokeCredentialsLocked(i)
		i.mu.Unlock()
		cancelStartup()
		cancelLifetime()
	})
	return i
}

func regressionScope(pairs ...string) *wire.ResourceScope {
	ids := make(map[string]string, len(pairs)/2)
	for n := 0; n < len(pairs); n += 2 {
		ids[pairs[n]] = pairs[n+1]
	}
	return &wire.ResourceScope{SelectorKind: &wire.ResourceScope_Selector{Selector: &wire.ResourceSelector{ResourceIds: ids}}}
}

func regressionRPC(t *testing.T, i *Instance, parent context.Context) context.Context {
	t.Helper()
	ctx, finish, err := i.beginRPC(parent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(finish)
	return ctx
}

func regressionError(t *testing.T, err error, code codes.Code, reason string) {
	t.Helper()
	if status.Code(err) != code || status.Convert(err).Message() != reason {
		t.Fatalf("got %v; want %s/%s", err, code, reason)
	}
}

func regressionWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("bounded runtime operation did not complete")
	}
}

// Observe entry into the actual START gate select, without scheduling sleeps.
// Err is inherited; Done is observed only after eligibleLocked releases i.mu.
type regressionGateContext struct {
	context.Context
	once    sync.Once
	waiting chan struct{}
}

func (c *regressionGateContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

// A real in-memory primary gRPC connection exercises the guard's installed
// stream interceptor, rather than calling its failure callback directly.
func regressionBrokerConnection(t *testing.T, guard *core.BrokerGuard, malformed bool) (*grpc.ClientConn, *dynamicpb.Message) {
	t.Helper()
	descriptor, err := protoregistry.GlobalFiles.FindDescriptorByName("plugin.ConnInfo")
	if err != nil {
		t.Fatal(err)
	}
	info, ok := descriptor.(protoreflect.MessageDescriptor)
	if !ok {
		t.Fatal("go-plugin ConnInfo descriptor is not a message")
	}
	listener := bufconn.Listen(4096)
	server := grpc.NewServer()
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "plugin.GRPCBroker",
		HandlerType: (*interface{})(nil),
		Streams: []grpc.StreamDesc{{
			StreamName: "StartStream", ClientStreams: true, ServerStreams: true,
			Handler: func(_ interface{}, stream grpc.ServerStream) error {
				if !malformed {
					return nil
				}
				message := dynamicpb.NewMessage(info)
				message.Set(info.Fields().ByNumber(1), protoreflect.ValueOfUint32(2))
				knockField := info.Fields().ByNumber(4)
				knock := dynamicpb.NewMessage(knockField.Message())
				knock.Set(knockField.Message().Fields().ByNumber(1), protoreflect.ValueOfBool(true))
				message.Set(knockField, protoreflect.ValueOfMessage(knock))
				if err := stream.SendMsg(message); err != nil {
					return err
				}
				<-stream.Context().Done()
				return stream.Context().Err()
			},
		}},
	}, struct{}{})
	t.Cleanup(server.Stop)
	t.Cleanup(func() { _ = listener.Close() })
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///runtime-broker-regression",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
		guard.DialOption(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, dynamicpb.NewMessage(info)
}
