package corev2

import (
	"context"
	"io"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

type brokerFixtureStream struct {
	ctx      context.Context
	incoming []proto.Message
	sent     int
}

func (s *brokerFixtureStream) Header() (metadata.MD, error) { return nil, nil }
func (s *brokerFixtureStream) Trailer() metadata.MD         { return nil }
func (s *brokerFixtureStream) CloseSend() error             { return nil }
func (s *brokerFixtureStream) Context() context.Context     { return s.ctx }
func (s *brokerFixtureStream) SendMsg(any) error            { s.sent++; return nil }
func (s *brokerFixtureStream) RecvMsg(value any) error {
	if len(s.incoming) == 0 {
		return io.EOF
	}
	message := value.(proto.Message)
	proto.Reset(message)
	proto.Merge(message, s.incoming[0])
	s.incoming = s.incoming[1:]
	return nil
}

func brokerFixtureMessage(g *BrokerGuard, id uint32, ack bool) *dynamicpb.Message {
	message := dynamicpb.NewMessage(g.schema.info)
	message.Set(g.schema.serviceID, protoreflect.ValueOfUint32(id))
	knock := dynamicpb.NewMessage(g.schema.knockMessage)
	knock.Set(g.schema.knockFlag, protoreflect.ValueOfBool(true))
	knock.Set(g.schema.ackFlag, protoreflect.ValueOfBool(ack))
	message.Set(g.schema.knock, protoreflect.ValueOfMessage(knock))
	return message
}

func TestBrokerGuardRejectsBeforePendingStateConsumer(t *testing.T) {
	cases := []struct {
		name   string
		change func(*BrokerGuard, *dynamicpb.Message)
	}{
		{"zero-id", func(g *BrokerGuard, m *dynamicpb.Message) { m.Set(g.schema.serviceID, protoreflect.ValueOfUint32(0)) }},
		{"unknown-id", func(g *BrokerGuard, m *dynamicpb.Message) { m.Set(g.schema.serviceID, protoreflect.ValueOfUint32(2)) }},
		{"largest-id", func(g *BrokerGuard, m *dynamicpb.Message) {
			m.Set(g.schema.serviceID, protoreflect.ValueOfUint32(math.MaxUint32))
		}},
		{"address", func(g *BrokerGuard, m *dynamicpb.Message) {
			m.Set(g.schema.address, protoreflect.ValueOfString("/untrusted/socket"))
		}},
		{"network", func(g *BrokerGuard, m *dynamicpb.Message) { m.Set(g.schema.network, protoreflect.ValueOfString("tcp")) }},
		{"missing-knock", func(g *BrokerGuard, m *dynamicpb.Message) { m.Clear(g.schema.knock) }},
		{"false-knock", func(g *BrokerGuard, m *dynamicpb.Message) {
			m.Get(g.schema.knock).Message().Set(g.schema.knockFlag, protoreflect.ValueOfBool(false))
		}},
		{"wrong-direction", func(g *BrokerGuard, m *dynamicpb.Message) {
			m.Get(g.schema.knock).Message().Set(g.schema.ackFlag, protoreflect.ValueOfBool(true))
		}},
		{"untrusted-error", func(g *BrokerGuard, m *dynamicpb.Message) {
			m.Get(g.schema.knock).Message().Set(g.schema.knockError, protoreflect.ValueOfString("RAW_SECRET"))
		}},
		{"unknown-top-field", func(g *BrokerGuard, m *dynamicpb.Message) {
			m.SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
		}},
		{"unknown-knock-field", func(g *BrokerGuard, m *dynamicpb.Message) {
			m.Get(g.schema.knock).Message().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			failures := 0
			guard, err := NewBrokerGuard(func(error) { failures++ })
			if err != nil {
				t.Fatal(err)
			}
			message := brokerFixtureMessage(guard, HelperBrokerID, false)
			tc.change(guard, message)
			stream := &guardedBrokerStream{guard: guard, ClientStream: &brokerFixtureStream{ctx: context.Background(), incoming: []proto.Message{message, brokerFixtureMessage(guard, HelperBrokerID, false)}}}
			pending := make(map[uint32]struct{})
			for range 2 {
				incoming := dynamicpb.NewMessage(guard.schema.info)
				if err := stream.RecvMsg(incoming); err == nil {
					// The real broker.Run allocation is downstream of RecvMsg.
					pending[uint32(incoming.Get(guard.schema.serviceID).Uint())] = struct{}{}
				}
			}
			if len(pending) != 0 || failures != 1 {
				t.Fatalf("pending=%d terminal callbacks=%d", len(pending), failures)
			}
		})
	}
}

func TestBrokerGuardOneKnockOneAckLifetime(t *testing.T) {
	failures := 0
	guard, err := NewBrokerGuard(func(error) { failures++ })
	if err != nil {
		t.Fatal(err)
	}
	fixture := &brokerFixtureStream{ctx: context.Background(), incoming: []proto.Message{brokerFixtureMessage(guard, HelperBrokerID, false), brokerFixtureMessage(guard, HelperBrokerID, false)}}
	stream := &guardedBrokerStream{guard: guard, ClientStream: fixture}
	if err := stream.RecvMsg(dynamicpb.NewMessage(guard.schema.info)); err != nil {
		t.Fatal(err)
	}
	if err := stream.SendMsg(brokerFixtureMessage(guard, HelperBrokerID, true)); err != nil {
		t.Fatal(err)
	}
	if err := stream.RecvMsg(dynamicpb.NewMessage(guard.schema.info)); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("second knock=%v", err)
	}
	if err := stream.SendMsg(brokerFixtureMessage(guard, HelperBrokerID, true)); err == nil {
		t.Fatal("reconnect acknowledgement forwarded")
	}
	if fixture.sent != 1 || failures != 1 {
		t.Fatalf("forwarded ACKs=%d failures=%d", fixture.sent, failures)
	}
}

func TestBrokerGuardRejectsUnsolicitedAckAndSecondControlStream(t *testing.T) {
	t.Run("unsolicited-ack", func(t *testing.T) {
		guard, err := NewBrokerGuard(func(error) {})
		if err != nil {
			t.Fatal(err)
		}
		fixture := &brokerFixtureStream{ctx: context.Background()}
		stream := &guardedBrokerStream{guard: guard, ClientStream: fixture}
		if err := stream.SendMsg(brokerFixtureMessage(guard, HelperBrokerID, true)); err == nil || fixture.sent != 0 {
			t.Fatal("unsolicited ACK reached transport")
		}
	})
	t.Run("second-control-stream", func(t *testing.T) {
		guard, err := NewBrokerGuard(func(error) {})
		if err != nil {
			t.Fatal(err)
		}
		allocations := 0
		streamer := func(ctx context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn, _ string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
			allocations++
			return &brokerFixtureStream{ctx: ctx}, nil
		}
		description := &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}
		conn := new(grpc.ClientConn)
		if _, err := guard.intercept(context.Background(), description, conn, brokerStreamMethod, streamer); err != nil {
			t.Fatal(err)
		}
		if err := guard.awaitPrimary(context.Background(), context.Background(), conn); err != nil {
			t.Fatal(err)
		}
		if _, err := guard.intercept(context.Background(), description, conn, brokerStreamMethod, streamer); err == nil || allocations != 1 {
			t.Fatal("second broker transport allocated")
		}
	})
}

func TestBrokerGuardRequiresSamePrimaryAndAllowsReentrantFailure(t *testing.T) {
	var guard *BrokerGuard
	var failures atomic.Int32
	var err error
	guard, err = NewBrokerGuard(func(error) { failures.Add(1); guard.Close() })
	if err != nil {
		t.Fatal(err)
	}
	streamer := func(ctx context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn, _ string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
		return &brokerFixtureStream{ctx: ctx}, nil
	}
	if _, err := guard.intercept(context.Background(), &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, new(grpc.ClientConn), brokerStreamMethod, streamer); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- guard.awaitPrimary(context.Background(), context.Background(), new(grpc.ClientConn)) }()
	select {
	case err := <-done:
		if status.Code(err) != codes.FailedPrecondition || failures.Load() != 1 {
			t.Fatalf("mismatched binding=%v callbacks=%d", err, failures.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("failure callback deadlocked reentering guard")
	}
}

func TestBrokerGuardClosePreservesEstablishedTransportUntilJoinedCleanup(t *testing.T) {
	failures := 0
	guard, err := NewBrokerGuard(func(error) { failures++ })
	if err != nil {
		t.Fatal(err)
	}
	var transportContext context.Context
	streamer := func(ctx context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn, _ string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
		transportContext = ctx
		return &brokerFixtureStream{ctx: ctx}, nil
	}
	stream, err := guard.intercept(context.Background(), &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, new(grpc.ClientConn), brokerStreamMethod, streamer)
	if err != nil {
		t.Fatal(err)
	}
	guard.Close()
	if transportContext.Err() != nil {
		t.Fatal("normal Close canceled the established transport before STOP")
	}
	if err := stream.RecvMsg(dynamicpb.NewMessage(guard.schema.info)); status.Code(err) != codes.Canceled || failures != 0 {
		t.Fatalf("expected teardown EOF=%v failures=%d", err, failures)
	}
	guard.streamCancel()
}
