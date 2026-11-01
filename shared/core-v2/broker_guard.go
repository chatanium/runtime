package corev2

import (
	"context"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

const brokerStreamMethod = "/plugin.GRPCBroker/StartStream"

// BrokerGuard admits exactly one reverse-helper knock and acknowledgement for
// one primary connection over the entire instance lifetime. Install DialOption
// on that primary go-plugin ClientConfig before Client(), never on a later
// helper connection. onFailure must be nonblocking and terminate the instance;
// it is called at most once, without a guard lock held.
//
// In pinned go-plugin 1.8, each blockedClientListener.Accept consumes one token
// from waitCh before one yamux session.Accept. AcceptKnock adds one token, not a
// permanent opening. Rejecting every second knock therefore permits at most one
// reverse gRPC connection, including an idle/incomplete first connection. Raw
// unknocked yamux streams remain in its bounded backlog and cannot unblock a
// second helper Accept. No reconnect or replacement connection is authorized.
type BrokerGuard struct {
	mu            sync.Mutex
	schema        *brokerSchema
	onFailure     func(error)
	ready         chan struct{}
	readyOnce     sync.Once
	primary       *grpc.ClientConn
	streamStarted bool
	streamCancel  context.CancelFunc
	knockSeen     bool
	ackSent       bool
	closed        bool
	failure       error
}

type brokerSchema struct {
	info         protoreflect.MessageDescriptor
	serviceID    protoreflect.FieldDescriptor
	network      protoreflect.FieldDescriptor
	address      protoreflect.FieldDescriptor
	knock        protoreflect.FieldDescriptor
	knockMessage protoreflect.MessageDescriptor
	knockFlag    protoreflect.FieldDescriptor
	ackFlag      protoreflect.FieldDescriptor
	knockError   protoreflect.FieldDescriptor
}

var brokerSchemaCache struct {
	sync.Once
	schema *brokerSchema
	err    error
}

// NewBrokerGuard requires a terminal failure callback. It uses the already
// linked go-plugin descriptor, not a duplicate wire schema or an internal import.
func NewBrokerGuard(onFailure func(error)) (*BrokerGuard, error) {
	if onFailure == nil {
		return nil, NewError(codes.InvalidArgument, ReasonInvalidArgument)
	}
	brokerSchemaCache.Do(func() {
		descriptor, err := protoregistry.GlobalFiles.FindDescriptorByName("plugin.ConnInfo")
		if err != nil {
			brokerSchemaCache.err = NewError(codes.FailedPrecondition, ReasonProtocolMismatch)
			return
		}
		info, ok := descriptor.(protoreflect.MessageDescriptor)
		if !ok || info.Fields().Len() != 4 {
			brokerSchemaCache.err = NewError(codes.FailedPrecondition, ReasonProtocolMismatch)
			return
		}
		schema := &brokerSchema{info: info}
		schema.serviceID = info.Fields().ByNumber(1)
		schema.network = info.Fields().ByNumber(2)
		schema.address = info.Fields().ByNumber(3)
		schema.knock = info.Fields().ByNumber(4)
		if !brokerField(schema.serviceID, "service_id", protoreflect.Uint32Kind) || !brokerField(schema.network, "network", protoreflect.StringKind) || !brokerField(schema.address, "address", protoreflect.StringKind) || !brokerField(schema.knock, "knock", protoreflect.MessageKind) {
			brokerSchemaCache.err = NewError(codes.FailedPrecondition, ReasonProtocolMismatch)
			return
		}
		schema.knockMessage = schema.knock.Message()
		if schema.knockMessage.Fields().Len() != 3 {
			brokerSchemaCache.err = NewError(codes.FailedPrecondition, ReasonProtocolMismatch)
			return
		}
		schema.knockFlag = schema.knockMessage.Fields().ByNumber(1)
		schema.ackFlag = schema.knockMessage.Fields().ByNumber(2)
		schema.knockError = schema.knockMessage.Fields().ByNumber(3)
		if !brokerField(schema.knockFlag, "knock", protoreflect.BoolKind) || !brokerField(schema.ackFlag, "ack", protoreflect.BoolKind) || !brokerField(schema.knockError, "error", protoreflect.StringKind) {
			brokerSchemaCache.err = NewError(codes.FailedPrecondition, ReasonProtocolMismatch)
			return
		}
		brokerSchemaCache.schema = schema
	})
	if brokerSchemaCache.err != nil {
		return nil, brokerSchemaCache.err
	}
	return &BrokerGuard{schema: brokerSchemaCache.schema, onFailure: onFailure, ready: make(chan struct{})}, nil
}

func brokerField(field protoreflect.FieldDescriptor, name protoreflect.Name, kind protoreflect.Kind) bool {
	return field != nil && field.Name() == name && field.Kind() == kind && !field.IsList() && !field.IsMap()
}

// DialOption preserves all go-plugin AutoMTLS and multiplex dial options.
func (g *BrokerGuard) DialOption() grpc.DialOption {
	return grpc.WithChainStreamInterceptor(g.intercept)
}

// Close disables future broker admission and suppresses expected teardown
// failures. It deliberately does not cancel the existing stream or close the
// helper transport: STOP cleanup may still use that authenticated connection.
// The ordinary joined broker/client cleanup remains responsible for transport.
func (g *BrokerGuard) Close() {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
}

func (g *BrokerGuard) reject(err error) error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return NewError(codes.Canceled, ReasonCanceled)
	}
	if g.failure != nil {
		failure := g.failure
		g.mu.Unlock()
		return failure
	}
	g.failure = err
	cancel := g.streamCancel
	callback := g.onFailure
	g.mu.Unlock()
	g.readyOnce.Do(func() { close(g.ready) })
	if cancel != nil {
		cancel()
	}
	callback(err)
	return err
}

func (g *BrokerGuard) intercept(ctx context.Context, descriptor *grpc.StreamDesc, conn *grpc.ClientConn, method string, streamer grpc.Streamer, options ...grpc.CallOption) (grpc.ClientStream, error) {
	if method != brokerStreamMethod {
		return streamer(ctx, descriptor, conn, method, options...)
	}
	if descriptor == nil || !descriptor.ClientStreams || !descriptor.ServerStreams {
		return nil, g.reject(NewError(codes.FailedPrecondition, ReasonProtocolMismatch))
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil, NewError(codes.Canceled, ReasonCanceled)
	}
	if g.failure != nil {
		failure := g.failure
		g.mu.Unlock()
		return nil, failure
	}
	if g.streamStarted {
		g.mu.Unlock()
		return nil, g.reject(NewError(codes.FailedPrecondition, ReasonProtocolMismatch))
	}
	g.streamStarted = true
	g.primary = conn
	bounded, cancel := context.WithCancel(ctx)
	g.streamCancel = cancel
	g.mu.Unlock()
	stream, err := streamer(bounded, descriptor, conn, method, options...)
	if err != nil {
		cancel()
		return nil, g.reject(NewError(codes.Unavailable, ReasonHelperUnavailable))
	}
	g.readyOnce.Do(func() { close(g.ready) })
	return &guardedBrokerStream{ClientStream: stream, guard: g}, nil
}

func (g *BrokerGuard) awaitPrimary(startup, lifetime context.Context, conn *grpc.ClientConn) error {
	select {
	case <-g.ready:
	case <-startup.Done():
		return SafeRPCError(startup.Err())
	case <-lifetime.Done():
		return SafeRPCError(lifetime.Err())
	}
	g.mu.Lock()
	failure, closed, primary := g.failure, g.closed, g.primary
	g.mu.Unlock()
	if failure != nil {
		return failure
	}
	if closed {
		return NewError(codes.Canceled, ReasonCanceled)
	}
	if primary != conn {
		return g.reject(NewError(codes.FailedPrecondition, ReasonProtocolMismatch))
	}
	return nil
}

func (g *BrokerGuard) validMessage(value any, ack bool) bool {
	message, ok := value.(proto.Message)
	if !ok || message == nil {
		return false
	}
	info := message.ProtoReflect()
	schema := g.schema
	if !info.IsValid() || info.Descriptor() != schema.info || len(info.GetUnknown()) != 0 || info.Get(schema.serviceID).Uint() != uint64(HelperBrokerID) || info.Get(schema.network).String() != "" || info.Get(schema.address).String() != "" || !info.Has(schema.knock) {
		return false
	}
	knock := info.Get(schema.knock).Message()
	return knock.IsValid() && knock.Descriptor() == schema.knockMessage && len(knock.GetUnknown()) == 0 && knock.Get(schema.knockFlag).Bool() && knock.Get(schema.ackFlag).Bool() == ack && knock.Get(schema.knockError).String() == ""
}

func (g *BrokerGuard) admit(value any, ack bool) error {
	if !g.validMessage(value, ack) {
		return g.reject(NewError(codes.FailedPrecondition, ReasonProtocolMismatch))
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return NewError(codes.Canceled, ReasonCanceled)
	}
	if g.failure != nil {
		failure := g.failure
		g.mu.Unlock()
		return failure
	}
	violation := g.knockSeen
	if ack {
		violation = !g.knockSeen || g.ackSent
	}
	if !violation {
		if ack {
			g.ackSent = true
		} else {
			g.knockSeen = true
		}
	}
	g.mu.Unlock()
	if violation {
		return g.reject(NewError(codes.FailedPrecondition, ReasonProtocolMismatch))
	}
	return nil
}

type guardedBrokerStream struct {
	grpc.ClientStream
	guard *BrokerGuard
}

func (s *guardedBrokerStream) RecvMsg(value any) error {
	if err := s.ClientStream.RecvMsg(value); err != nil {
		return s.guard.reject(NewError(codes.Unavailable, ReasonHelperUnavailable))
	}
	// Returning an error here prevents StartStream from handing ConnInfo to
	// its recv channel; broker.Run cannot allocate any pending state for it.
	return s.guard.admit(value, false)
}

func (s *guardedBrokerStream) SendMsg(value any) error {
	if err := s.guard.admit(value, true); err != nil {
		return err
	}
	if err := s.ClientStream.SendMsg(value); err != nil {
		return s.guard.reject(NewError(codes.Unavailable, ReasonHelperUnavailable))
	}
	return nil
}
