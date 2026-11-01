package runtime

import (
	"context"
	"testing"
	"time"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func regressionEvent(t *testing.T, value string) BackendEvent {
	t.Helper()
	payload, err := anypb.New(wrapperspb.String(value))
	if err != nil {
		t.Fatal(err)
	}
	return BackendEvent{
		BackendID: regressionBackend, BackendMajor: 1, EventType: "changed", Operation: "write",
		Scope: regressionScope("group", "a"), ReceivedAt: time.Unix(1700000000, 0),
		Project: func(context.Context, InstancePrincipal) (*anypb.Any, error) { return payload, nil },
	}
}

func regressionQueuedEvents(t *testing.T, i *Instance) []*wire.EventEnvelope {
	t.Helper()
	i.mu.Lock()
	defer i.mu.Unlock()
	var events []*wire.EventEnvelope
	var queuedBytes int64
	for _, raw := range i.queue {
		e := new(wire.EventEnvelope)
		if err := proto.Unmarshal(raw, e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
		queuedBytes += int64(len(raw))
	}
	if i.retainedCount < len(events) || i.retainedBytes < queuedBytes {
		t.Fatal("queue exceeds retained resource reservation")
	}
	return events
}

func TestEventFIFOAndOverflowAreInstanceLocal(t *testing.T) {
	for _, inflight := range []bool{false, true} {
		name := "queued"
		if inflight {
			name = "retained-inflight"
		}
		t.Run(name, func(t *testing.T) {
			m := regressionManager()
			slow := regressionInstance(t, m, "slow")
			healthy := regressionInstance(t, m, "healthy")
			// This fixture owns only admission, not a platform/lifecycle worker.
			// Mark teardown owned so overflow cannot launch host cleanup.
			slow.stopStarted = true
			first := regressionEvent(t, "first")
			first.Recipient = func(p InstancePrincipal) bool { return p == slow.principal }
			if err := m.dispatcher.Admit(context.Background(), first); err != nil {
				t.Fatal(err)
			}
			firstEvents := regressionQueuedEvents(t, slow)
			if len(firstEvents) != 1 || firstEvents[0].IngressSequence != 1 {
				t.Fatal("first ingress was not retained")
			}
			var inflightBytes int64
			if inflight {
				// Model the eventLane's dequeue boundary without a fake hook:
				// the serialized delivery leaves FIFO but still owns its budget.
				slow.mu.Lock()
				inflightBytes = int64(len(slow.queue[0]))
				slow.queue = nil
				slow.mu.Unlock()
			}
			if err := m.dispatcher.Admit(context.Background(), regressionEvent(t, "second")); err != nil {
				t.Fatal(err)
			}
			before := slow.Snapshot()
			if before.RetainedEvents != 2 || before.RetainedBytes <= inflightBytes {
				t.Fatal("queued and in-flight reservations did not accumulate")
			}
			queued := regressionQueuedEvents(t, slow)
			if inflight {
				if len(queued) != 1 || queued[0].IngressSequence != 2 {
					t.Fatal("in-flight delivery was counted as queued")
				}
			} else if len(queued) != 2 || queued[0].IngressSequence != 1 || queued[1].IngressSequence != 2 {
				t.Fatal("admission reordered per-instance FIFO")
			}
			if err := m.dispatcher.Admit(context.Background(), regressionEvent(t, "third")); err != nil {
				t.Fatal(err)
			}
			failed, survivor := slow.Snapshot(), healthy.Snapshot()
			if failed.State != Failed || failed.FailureReason != "EVENT_QUEUE_OVERFLOW" || failed.IncompleteEvents != 2 {
				t.Fatalf("saturated recipient did not fail with its exact incomplete reservation: %+v", failed)
			}
			if failed.RetainedEvents != 2 || failed.RetainedBytes != before.RetainedBytes || len(regressionQueuedEvents(t, slow)) != 0 {
				t.Fatal("overflow admitted the offending event or lost failure accounting")
			}
			if survivor.State != Running || survivor.FailureReason != "" || survivor.IncompleteEvents != 0 || survivor.RetainedEvents != 2 {
				t.Fatalf("one recipient's overflow damaged another recipient: %+v", survivor)
			}
			remaining := regressionQueuedEvents(t, healthy)
			if len(remaining) != 2 || remaining[0].IngressSequence != 2 || remaining[1].IngressSequence != 3 {
				t.Fatal("healthy FIFO lost global ingress ordering")
			}
			for n, expected := range []string{"second", "third"} {
				value := new(wrapperspb.StringValue)
				if err := remaining[n].Payload.UnmarshalTo(value); err != nil || value.Value != expected {
					t.Fatalf("healthy payload %d: %v %v", n, value, err)
				}
			}
		})
	}
}

func TestEventProjectionCannotCommitAfterAuthorityChanges(t *testing.T) {
	for _, change := range []string{"state", "grant"} {
		t.Run(change, func(t *testing.T) {
			m := regressionManager()
			i := regressionInstance(t, m, "owner")
			event := regressionEvent(t, "not-admitted")
			project := event.Project
			event.Project = func(ctx context.Context, p InstancePrincipal) (*anypb.Any, error) {
				i.mu.Lock()
				if change == "state" {
					i.state = Draining
				} else {
					i.grants.Backends[0].Capabilities[0].ResourceScopes = []*wire.ResourceScope{regressionScope("group", "b")}
				}
				i.mu.Unlock()
				return project(ctx, p)
			}
			if err := m.dispatcher.Admit(context.Background(), event); err != nil {
				t.Fatal(err)
			}
			snapshot := i.Snapshot()
			if snapshot.RetainedEvents != 0 || snapshot.RetainedBytes != 0 || len(regressionQueuedEvents(t, i)) != 0 {
				t.Fatal("projection's stale eligibility check committed an event")
			}
		})
	}
}

func TestEventScopeMustMatchWholeSelector(t *testing.T) {
	m := regressionManager()
	i := regressionInstance(t, m, "owner")
	i.grants.Backends[0].Capabilities[0].ResourceScopes = []*wire.ResourceScope{regressionScope("group", "a", "item", "one")}
	event := regressionEvent(t, "denied")
	event.Scope = regressionScope("group", "a", "item", "two")
	projected := false
	event.Project = func(context.Context, InstancePrincipal) (*anypb.Any, error) { projected = true; return nil, nil }
	if err := m.dispatcher.Admit(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if projected || i.Snapshot().RetainedEvents != 0 {
		t.Fatal("partial selector match reached projection")
	}
	// An ingress event cannot claim a wildcard as a resolved resource fact.
	event.Scope = &wire.ResourceScope{SelectorKind: &wire.ResourceScope_AllResources{AllResources: true}}
	err := m.dispatcher.Admit(context.Background(), event)
	regressionError(t, err, codes.InvalidArgument, "BACKEND_DISPATCH_INVALID")
}
