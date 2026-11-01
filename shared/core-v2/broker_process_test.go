package corev2

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const brokerFixtureEnv = "FLEXMODULE_BROKER_GUARD_FIXTURE"

// This fixture exercises the actual pinned go-plugin primary/multiplex broker
// and AutoMTLS in two processes. It is a transport regression, not a substitute
// for runtime sandbox/authority or P3 upload-store acceptance.
func TestBrokerGuardModuleProcess(t *testing.T) {
	mode := os.Getenv(brokerFixtureEnv)
	if mode == "" {
		return
	}
	hooks := &brokerProcessHooks{mode: mode}
	module, err := NewModulePlugin(context.Background(), hooks, func(ctx context.Context, conn grpc.ClientConnInterface) error {
		config, err := NewCoreClient(conn, JSONLimits{MaxBytes: 1024, MaxDepth: 1024})
		if err != nil {
			return err
		}
		value, err := config.GetConfig(ctx)
		if err != nil {
			return err
		}
		if !bytes.Equal(value.Json, []byte(`{"fixture":9007199254740993}`)) {
			return errors.New("fixture configuration changed")
		}
		files, err := NewFileClient(conn)
		if err != nil {
			return err
		}
		body := []byte("bounded upload fixture")
		ref, err := files.Upload(ctx, &wire.UploadMetadata{FileName: "fixture.txt", ContentType: "text/plain", DeclaredSizeBytes: uint64(len(body))}, bytes.NewReader(body))
		if err != nil {
			return err
		}
		if ref.SizeBytes != uint64(len(body)) {
			return errors.New("fixture upload changed")
		}
		hooks.mu.Lock()
		hooks.config = config
		hooks.mu.Unlock()
		hooks.ready.Store(true)
		return nil
	}, TransportLimits{MaxReceiveBytes: 4096, MaxSendBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	capture := &brokerProcessPlugin{ModulePlugin: module, hooks: hooks}
	config := module.ServeConfig()
	config.Plugins = plugin.PluginSet{PluginKey: capture}
	if mode == "unknown-ids" || mode == "repeated-knocks" {
		config.GRPCServer = func(options []grpc.ServerOption) *grpc.Server {
			options = append(options, grpc.MaxRecvMsgSize(4096), grpc.MaxSendMsgSize(4096), grpc.ChainStreamInterceptor(func(server any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
				if info.FullMethod != brokerStreamMethod {
					return handler(server, stream)
				}
				schema, err := NewBrokerGuard(func(error) {})
				if err != nil {
					return err
				}
				for n := range 1024 {
					id := HelperBrokerID
					if mode == "unknown-ids" {
						id = uint32(n) + 2
					}
					if err := stream.SendMsg(brokerFixtureMessage(schema, id, false)); err != nil {
						return err
					}
				}
				<-stream.Context().Done()
				return stream.Context().Err()
			}))
			return plugin.DefaultGRPCServer(options)
		}
	}
	plugin.Serve(config)
}

type brokerProcessPlugin struct {
	*ModulePlugin
	hooks *brokerProcessHooks
}

func (p *brokerProcessPlugin) GRPCServer(broker *plugin.GRPCBroker, server *grpc.Server) error {
	p.hooks.broker = broker
	return p.ModulePlugin.GRPCServer(broker, server)
}

type brokerProcessHooks struct {
	mode   string
	broker *plugin.GRPCBroker
	mu     sync.Mutex
	config CoreClient
	ready  atomic.Bool
	attack sync.Once
}

func (h *brokerProcessHooks) GetManifest(ctx context.Context) (*wire.ModuleManifest, error) {
	if h.mode == "idle-incomplete" {
		h.attack.Do(func() {
			started := make(chan struct{})
			connection, err := h.broker.DialWithOptions(HelperBrokerID, grpc.WithTransportCredentials(&brokerStalledTLS{started: started}))
			if err != nil {
				return
			}
			connection.Connect()
			select {
			case <-started:
				// The first permitted yamux stream has reached TLS but sends no
				// handshake bytes. A second knock must fail before another helper
				// transport can be accepted, despite the first never issuing RPCs.
				second, err := h.broker.DialWithOptions(HelperBrokerID)
				if err == nil {
					second.Connect()
				}
			case <-ctx.Done():
				_ = connection.Close()
			}
		})
	}
	return &wire.ModuleManifest{ProtocolMajor: ProtocolMajor, Name: "broker-transport-fixture"}, nil
}
func (h *brokerProcessHooks) GetStatus(context.Context) (*wire.Status, error) {
	readiness := wire.Readiness_READINESS_NOT_READY
	if h.ready.Load() {
		readiness = wire.Readiness_READINESS_READY
	}
	return &wire.Status{Readiness: readiness}, nil
}
func (h *brokerProcessHooks) OnStage(ctx context.Context, request *wire.StageRequest) error {
	if request.Stage != wire.Stage_STAGE_STOP {
		return nil
	}
	h.mu.Lock()
	config := h.config
	h.mu.Unlock()
	if config == nil {
		return errors.New("STOP has no bound helper client")
	}
	// Guard.Close must leave this already-established helper transport usable
	// until the module's STOP callback finishes and ordinary joined cleanup runs.
	_, err := config.GetConfig(ctx)
	return err
}
func (*brokerProcessHooks) OnEvent(context.Context, *wire.EventEnvelope) error { return nil }

// Only the attacking module side overrides its TLS behavior; host AutoMTLS
// credentials are never changed. Stalling before ClientHandshake writes models
// an idle/incomplete reverse connection rather than a valid authenticated RPC.
type brokerStalledTLS struct {
	started chan struct{}
	once    sync.Once
}

func (c *brokerStalledTLS) ClientHandshake(ctx context.Context, _ string, connection net.Conn) (net.Conn, credentials.AuthInfo, error) {
	c.once.Do(func() { close(c.started) })
	<-ctx.Done()
	_ = connection.Close()
	return nil, nil, ctx.Err()
}
func (*brokerStalledTLS) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("fixture is client-only")
}
func (*brokerStalledTLS) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls"}
}
func (c *brokerStalledTLS) Clone() credentials.TransportCredentials { return c }
func (*brokerStalledTLS) OverrideServerName(string) error           { return nil }

type brokerProcessCore struct{ wire.UnimplementedCoreServer }

func (*brokerProcessCore) GetConfig(context.Context, *emptypb.Empty) (*wire.JSONValue, error) {
	return &wire.JSONValue{Json: []byte(`{"fixture":9007199254740993}`)}, nil
}

type brokerProcessFiles struct {
	wire.UnimplementedFileTransferServer
}

func (*brokerProcessFiles) Upload(stream grpc.ClientStreamingServer[wire.UploadChunk, wire.UploadedFileRef]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	metadata := first.GetMetadata()
	if metadata == nil || metadata.DeclaredSizeBytes > MaxUploadFileBytes {
		return NewError(codes.InvalidArgument, ReasonUploadSequence)
	}
	var received uint64
	for {
		message, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		chunk := message.GetChunk()
		if chunk == nil || len(chunk.Data) == 0 || len(chunk.Data) > MaxUploadChunkBytes || chunk.Offset != received || uint64(len(chunk.Data)) > metadata.DeclaredSizeBytes-received {
			return NewError(codes.InvalidArgument, ReasonUploadSequence)
		}
		received += uint64(len(chunk.Data))
	}
	if received != metadata.DeclaredSizeBytes {
		return NewError(codes.InvalidArgument, ReasonUploadSizeMismatch)
	}
	return stream.SendAndClose(&wire.UploadedFileRef{OpaqueId: "transport-fixture", FileName: metadata.FileName, ContentType: metadata.ContentType, SizeBytes: received, ExpiresAt: timestamppb.New(time.Now().Add(time.Minute))})
}
func (*brokerProcessFiles) DeleteUpload(_ context.Context, request *wire.DeleteUploadRequest) (*emptypb.Empty, error) {
	if request.File == nil || request.File.OpaqueId != "transport-fixture" {
		return nil, NewError(codes.NotFound, ReasonRefNotFound)
	}
	return &emptypb.Empty{}, nil
}

func TestBrokerGuardActualGoPluginAutoMTLSMultiplex(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"legitimate", "unknown-ids", "repeated-knocks", "idle-incomplete"} {
		t.Run(mode, func(t *testing.T) {
			startup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			failures := make(chan error, 1)
			guard, err := NewBrokerGuard(func(err error) { failures <- err })
			if err != nil {
				t.Fatal(err)
			}
			registrars := []HelperRegistrar{
				func(server grpc.ServiceRegistrar) error {
					wire.RegisterCoreServer(server, &brokerProcessCore{})
					return nil
				},
				func(server grpc.ServiceRegistrar) error {
					wire.RegisterFileTransferServer(server, &brokerProcessFiles{})
					return nil
				},
			}
			bridge, err := NewHostPlugin(startup, func(options []grpc.ServerOption) (*grpc.Server, error) { return grpc.NewServer(options...), nil }, registrars, TransportLimits{MaxReceiveBytes: 4096, MaxSendBytes: 4096}, guard)
			if err != nil {
				t.Fatal(err)
			}
			command := exec.Command(executable, "-test.run=^TestBrokerGuardModuleProcess$")
			command.Env = []string{brokerFixtureEnv + "=" + mode}
			client := plugin.NewClient(&plugin.ClientConfig{
				HandshakeConfig: HandshakeConfig(), Plugins: bridge.PluginMap(), Cmd: command,
				AutoMTLS: true, SkipHostEnv: true, GRPCBrokerMultiplex: true, AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
				StartTimeout: 10 * time.Second, Logger: hclog.NewNullLogger(), Stderr: io.Discard, SyncStdout: io.Discard, SyncStderr: io.Discard,
				UnixSocketConfig: &plugin.UnixSocketConfig{TempDir: t.TempDir()},
				GRPCDialOptions:  []grpc.DialOption{grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(4096), grpc.MaxCallSendMsgSize(4096)), guard.DialOption()},
			})
			t.Cleanup(func() { guard.Close(); client.Kill() })
			rpc, err := client.Client()
			if err != nil {
				t.Fatalf("fixture primary bootstrap: %v", err)
			}
			value, dispenseErr := rpc.Dispense(PluginKey)
			if mode != "legitimate" {
				if dispenseErr == nil {
					hooks := value.(*HookClient)
					_, _ = hooks.GetManifest(startup)
				}
				select {
				case err := <-failures:
					if status.Code(err) != codes.FailedPrecondition {
						t.Fatalf("attack did not cause protocol failure: %v", err)
					}
				case <-startup.Done():
					t.Fatal("untrusted broker traffic did not fail the instance")
				}
				if mode == "idle-incomplete" {
					guard.mu.Lock()
					knocked, acked := guard.knockSeen, guard.ackSent
					guard.mu.Unlock()
					if !knocked || !acked {
						t.Fatal("fixture never established its one allowed incomplete connection")
					}
				}
				return
			}
			if dispenseErr != nil {
				t.Fatal(dispenseErr)
			}
			hooks := value.(*HookClient)
			manifest, err := hooks.GetManifest(startup)
			if err != nil || manifest.ProtocolMajor != ProtocolMajor {
				t.Fatalf("manifest=%v err=%v", manifest, err)
			}
			if err := hooks.OnStage(startup, &wire.StageRequest{Stage: wire.Stage_STAGE_INIT, InitContext: &wire.InitContext{ModuleId: "fixture", InstanceId: "fixture-instance", Grants: &wire.Grants{}}}); err != nil {
				t.Fatal(err)
			}
			statusValue, err := hooks.GetStatus(startup)
			if err != nil || statusValue.Readiness != wire.Readiness_READINESS_READY {
				t.Fatalf("helper binding/config/upload failed: %v %v", statusValue, err)
			}
			if err := hooks.OnStage(startup, &wire.StageRequest{Stage: wire.Stage_STAGE_START}); err != nil {
				t.Fatal(err)
			}
			guard.Close()
			if err := hooks.OnStage(startup, &wire.StageRequest{Stage: wire.Stage_STAGE_STOP}); err != nil {
				t.Fatal(err)
			}
			if err := hooks.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-failures:
				t.Fatalf("legitimate bootstrap/STOP failed: %v", err)
			default:
			}
			if !proto.Equal(manifest, &wire.ModuleManifest{ProtocolMajor: ProtocolMajor, Name: "broker-transport-fixture"}) {
				t.Fatal("fixture manifest changed")
			}
		})
	}
}
