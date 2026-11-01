package corev2

import (
	"context"
	"sync"
	"time"

	plugin "github.com/hashicorp/go-plugin"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
)

// HandshakeConfig returns a fresh application-v2 handshake. The cookie only
// detects accidental execution; AutoMTLS and the trusted host binding establish
// connection authentication, not this public cookie.
func HandshakeConfig() plugin.HandshakeConfig {
	return plugin.HandshakeConfig{
		ProtocolVersion:  ProtocolMajor,
		MagicCookieKey:   "FLEXMODULE_PLUGIN",
		MagicCookieValue: "CHATANIUM_FOREVER",
	}
}

// ModulePlugin exposes Hook over the primary go-plugin connection and owns the
// single reverse helper connection. No backend package is imported here.
// Construct one plugin per process/instance; it cannot be reinitialized.
type ModulePlugin struct {
	plugin.NetRPCUnsupportedPlugin
	ctx         context.Context
	cancel      context.CancelFunc
	hooks       ModuleHooks
	bind        HelperBinder
	limits      TransportLimits
	mu          sync.Mutex
	broker      *plugin.GRPCBroker
	conn        *grpc.ClientConn
	initStarted bool
	closed      bool
}

var _ plugin.GRPCPlugin = (*ModulePlugin)(nil)

// NewModulePlugin binds an explicit process lifetime, hooks, helper-client binder
// and finite RPC limits. The binder runs before the user's INIT callback. Cancel
// lifetime or call Close to terminate all owned helper work on startup failure.
func NewModulePlugin(lifetime context.Context, hooks ModuleHooks, bind HelperBinder, limits TransportLimits) (*ModulePlugin, error) {
	if lifetime == nil || hooks == nil || bind == nil || !limits.valid() {
		return nil, NewError(codes.InvalidArgument, ReasonInvalidArgument)
	}
	ctx, cancel := context.WithCancel(lifetime)
	return &ModulePlugin{ctx: ctx, cancel: cancel, hooks: hooks, bind: bind, limits: limits}, nil
}

// PluginMap returns the one and only v2 plugin key. The caller serves it with
// HandshakeConfig and grpc support; stdout before the handshake is forbidden.
func (p *ModulePlugin) PluginMap() plugin.PluginSet { return plugin.PluginSet{PluginKey: p} }

// ServeConfig supplies the complete module bootstrap configuration, preserving
// go-plugin's TLS options and applying finite primary-server RPC limits. Pass
// this to plugin.Serve; do not print to stdout before Serve's handshake.
func (p *ModulePlugin) ServeConfig() *plugin.ServeConfig {
	return &plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig(),
		Plugins:         p.PluginMap(),
		GRPCServer: func(opts []grpc.ServerOption) *grpc.Server {
			options := append([]grpc.ServerOption(nil), opts...)
			options = append(options, grpc.MaxRecvMsgSize(p.limits.MaxReceiveBytes), grpc.MaxSendMsgSize(p.limits.MaxSendBytes))
			return plugin.DefaultGRPCServer(options)
		},
	}
}

// GRPCServer implements go-plugin's module registration boundary.
func (p *ModulePlugin) GRPCServer(broker *plugin.GRPCBroker, server *grpc.Server) error {
	p.mu.Lock()
	if p.broker != nil || p.closed {
		p.mu.Unlock()
		return NewError(codes.FailedPrecondition, ReasonAlreadyInitialized)
	}
	p.broker = broker
	p.mu.Unlock()
	wire.RegisterHookServer(server, &moduleServer{plugin: p})
	context.AfterFunc(p.ctx, func() { _ = p.Close() })
	return nil
}

// GRPCClient rejects using a module-side plugin as a host-side plugin.
func (p *ModulePlugin) GRPCClient(context.Context, *plugin.GRPCBroker, *grpc.ClientConn) (interface{}, error) {
	return nil, NewError(codes.FailedPrecondition, ReasonProtocolMismatch)
}

func (p *ModulePlugin) connectHelpers(ctx context.Context) error {
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil {
		p.mu.Unlock()
		return NewError(codes.Unavailable, ReasonHelperUnavailable)
	}
	if p.initStarted {
		p.mu.Unlock()
		return NewError(codes.FailedPrecondition, ReasonAlreadyInitialized)
	}
	p.initStarted = true
	broker := p.broker
	p.mu.Unlock()
	if broker == nil {
		return NewError(codes.Unavailable, ReasonHelperUnavailable)
	}
	// DialWithOptions is nonblocking in go-plugin 1.8.0. Do not add WithBlock:
	// waiting below uses the caller context and owns/cleans the connection.
	conn, err := broker.DialWithOptions(HelperBrokerID,
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(p.limits.MaxReceiveBytes), grpc.MaxCallSendMsgSize(p.limits.MaxSendBytes)))
	if err != nil {
		_ = p.Close()
		return NewError(codes.Unavailable, ReasonHelperUnavailable)
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = conn.Close()
		return NewError(codes.Unavailable, ReasonHelperUnavailable)
	}
	p.conn = conn
	p.mu.Unlock()
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stopLifetime := context.AfterFunc(p.ctx, cancel)
	defer stopLifetime()
	fail := func(err error) error { _ = p.Close(); return err }
	for {
		if err := startup.Err(); err != nil {
			return fail(SafeRPCError(err))
		}
		state := conn.GetState()
		if state == connectivity.Ready {
			break
		}
		if state == connectivity.Shutdown {
			return fail(NewError(codes.Unavailable, ReasonHelperUnavailable))
		}
		conn.Connect()
		if !conn.WaitForStateChange(startup, state) {
			return fail(SafeRPCError(startup.Err()))
		}
	}
	if err := p.bind(startup, helperConnection{conn: conn}); err != nil {
		return fail(SafeRPCError(err))
	}
	if err := startup.Err(); err != nil {
		return fail(SafeRPCError(err))
	}
	return nil
}

// Close cancels and closes owned helper transport. It is safe to call repeatedly
// and does not wait for user callbacks that ignore cancellation.
func (p *ModulePlugin) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	conn, broker := p.conn, p.broker
	p.mu.Unlock()
	p.cancel()
	if conn != nil {
		_ = conn.Close()
	}
	if broker != nil {
		return broker.Close()
	}
	return nil
}

// HostPlugin owns one reverse helper acceptor and returns *HookClient from
// go-plugin Dispense. The host injects its authenticated per-instance server
// factory and concrete core/file/backend registrars. There is no authorization
// fallback: this SDK neither invents grants nor installs permissive services.
type HostPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	startup    context.Context
	factory    HelperServerFactory
	registrars []HelperRegistrar
	limits     TransportLimits
	guard      *BrokerGuard
	mu         sync.Mutex
	started    bool
}

var _ plugin.GRPCPlugin = (*HostPlugin)(nil)

// NewHostPlugin captures the single global startup context, trusted server
// factory, finite limits and all concrete registrars (Core and FileTransfer must
// be included). P4 must configure its go-plugin ClientConfig with AutoMTLS=true,
// GRPCBrokerMultiplex=true, SkipHostEnv=true and AllowedProtocols=[ProtocolGRPC].
// RunnerFunc, primary path confinement and instance cleanup remain host-owned.
// guard.DialOption must be installed on the same primary ClientConfig before
// Client is called. Helper startup rejects absent/mismatched guard binding.
func NewHostPlugin(startup context.Context, factory HelperServerFactory, registrars []HelperRegistrar, limits TransportLimits, guard *BrokerGuard) (*HostPlugin, error) {
	if startup == nil || factory == nil || guard == nil || len(registrars) == 0 || !limits.valid() {
		return nil, NewError(codes.InvalidArgument, ReasonInvalidArgument)
	}
	for _, registrar := range registrars {
		if registrar == nil {
			return nil, NewError(codes.InvalidArgument, ReasonInvalidArgument)
		}
	}
	return &HostPlugin{startup: startup, factory: factory, registrars: append([]HelperRegistrar(nil), registrars...), limits: limits, guard: guard}, nil
}

// PluginMap returns the complete host plugin map for application protocol v2.
func (p *HostPlugin) PluginMap() plugin.PluginSet { return plugin.PluginSet{PluginKey: p} }

// GRPCServer rejects serving a host-side plugin as a module.
func (p *HostPlugin) GRPCServer(*plugin.GRPCBroker, *grpc.Server) error {
	return NewError(codes.FailedPrecondition, ReasonProtocolMismatch)
}

// GRPCClient starts exactly one reverse acceptor. It waits for actual listener
// establishment and service registration, not Dial or Serve completion, avoiding
// the sequential multiplex broker deadlock. Early acceptor exit is an error.
func (p *HostPlugin) GRPCClient(lifetime context.Context, broker *plugin.GRPCBroker, conn *grpc.ClientConn) (interface{}, error) {
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return nil, NewError(codes.FailedPrecondition, ReasonAlreadyInitialized)
	}
	p.started = true
	p.mu.Unlock()
	startup, cancel := context.WithTimeout(p.startup, 30*time.Second)
	defer cancel()
	if err := p.guard.awaitPrimary(startup, lifetime, conn); err != nil {
		return nil, err
	}
	a := &helperAcceptor{broker: broker, errors: make(chan error, 1)}
	ready := make(chan error, 1)
	done := make(chan struct{})
	stopLifetime := context.AfterFunc(lifetime, a.close)
	go func() {
		defer close(done)
		defer close(a.errors)
		defer stopLifetime()
		broker.AcceptAndServe(HelperBrokerID, func(brokerOptions []grpc.ServerOption) *grpc.Server {
			opts := append([]grpc.ServerOption(nil), brokerOptions...)
			opts = append(opts, grpc.MaxRecvMsgSize(p.limits.MaxReceiveBytes), grpc.MaxSendMsgSize(p.limits.MaxSendBytes))
			server, err := p.factory(opts)
			if err == nil && server == nil {
				err = NewError(codes.Internal, ReasonHelperStartup)
			}
			if err == nil {
				for _, registrar := range p.registrars {
					if err = registrar(server); err != nil {
						break
					}
				}
			}
			if err == nil {
				services := server.GetServiceInfo()
				if _, ok := services["flexmodule.core.v2.Core"]; !ok {
					err = NewError(codes.FailedPrecondition, ReasonHelperStartup)
				}
				if _, ok := services["flexmodule.core.v2.FileTransfer"]; !ok {
					err = NewError(codes.FailedPrecondition, ReasonHelperStartup)
				}
			}
			if err != nil {
				// AcceptAndServe cannot return factory errors and requires a nonnil
				// server. A stopped server only unwinds that API; it serves no RPCs.
				if server == nil {
					server = grpc.NewServer(opts...)
				}
				server.Stop()
				ready <- NewError(codes.Unavailable, ReasonHelperStartup)
				return server
			}
			a.mu.Lock()
			a.server = server
			closed := a.closed
			a.mu.Unlock()
			if closed {
				server.Stop()
				ready <- NewError(codes.Unavailable, ReasonHelperStartup)
			} else {
				ready <- nil
			}
			return server
		})
		a.mu.Lock()
		closed := a.closed
		a.mu.Unlock()
		if !closed {
			a.errors <- NewError(codes.Unavailable, ReasonHelperUnavailable)
		}
	}()
	select {
	case err := <-ready:
		if err != nil {
			a.close()
			return nil, err
		}
		select {
		case <-done:
			a.close()
			return nil, NewError(codes.Unavailable, ReasonHelperStartup)
		default:
		}
		if err := startup.Err(); err != nil {
			a.close()
			return nil, SafeRPCError(err)
		}
		if lifetime.Err() != nil {
			a.close()
			return nil, SafeRPCError(lifetime.Err())
		}
		return &HookClient{
			client: wire.NewHookClient(conn), helpers: a,
			options: []grpc.CallOption{grpc.MaxCallRecvMsgSize(p.limits.MaxReceiveBytes), grpc.MaxCallSendMsgSize(p.limits.MaxSendBytes)},
		}, nil
	case <-done:
		a.close()
		return nil, NewError(codes.Unavailable, ReasonHelperStartup)
	case <-startup.Done():
		a.close()
		return nil, SafeRPCError(startup.Err())
	case <-lifetime.Done():
		a.close()
		return nil, SafeRPCError(lifetime.Err())
	}
}

type helperAcceptor struct {
	mu     sync.Mutex
	broker *plugin.GRPCBroker
	server *grpc.Server
	closed bool
	errors chan error
}

func (a *helperAcceptor) close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	server := a.server
	a.mu.Unlock()
	if server != nil {
		server.Stop()
	}
	_ = a.broker.Close()
}

// helperConnection enforces work-reference-only metadata even when a backend
// binder installs generated clients directly rather than convenience wrappers.
type helperConnection struct{ conn *grpc.ClientConn }

func (c helperConnection) Invoke(ctx context.Context, method string, args, reply any, opts ...grpc.CallOption) error {
	return c.conn.Invoke(HelperContext(ctx), method, args, reply, opts...)
}

func (c helperConnection) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return c.conn.NewStream(HelperContext(ctx), desc, method, opts...)
}

func (p *ModulePlugin) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(p.ctx, cancel)
	if p.ctx.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}
