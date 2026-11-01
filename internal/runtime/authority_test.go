package runtime

import (
	"context"
	"testing"
	"time"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestAuthorizeAllTargetsAtomically(t *testing.T) {
	for _, scopes := range [][]*wire.ResourceScope{
		{regressionScope("group", "a"), regressionScope("group", "outside")},
		{regressionScope("group", "outside"), regressionScope("group", "a")},
		{regressionScope("group", "a"), nil},
		{regressionScope("group", "a"), regressionScope("unknown", "a")},
		{regressionScope("group", "a"), {SelectorKind: &wire.ResourceScope_AllResources{AllResources: true}}},
		nil,
	} {
		t.Run("denied-target", func(t *testing.T) {
			i := regressionInstance(t, regressionManager(), "owner")
			ctx := regressionRPC(t, i, context.Background())
			a := &Authorizer{instance: i}
			_, err := a.Authorize(ctx, AccessRequest{Backend: regressionBackend, Operation: "write", Scopes: scopes})
			regressionError(t, err, codes.PermissionDenied, "RESOURCE_SCOPE_DENIED")
			if len(i.admissions) != 0 || len(ctx.Value(principalKey{}).(*rpcCall).admissions) != 0 {
				t.Fatal("failed multi-target request left an authority lease")
			}
			if _, err := AdmissionFromContext(ctx); err == nil {
				t.Fatal("failed request exposes an admission")
			}
			// Different grant alternatives cover different required targets. A
			// failed attempt must not poison or partially admit the same RPC.
			p, err := a.Authorize(ctx, AccessRequest{Backend: regressionBackend, Operation: "write", Scopes: []*wire.ResourceScope{
				regressionScope("group", "a", "item", "one"), regressionScope("group", "b", "item", "two"),
			}})
			if err != nil || p != i.principal || len(i.admissions) != 1 {
				t.Fatalf("complete target admission: principal=%v leases=%d err=%v", p, len(i.admissions), err)
			}
			admission, err := AdmissionFromContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			grant, err := admission.CapabilityGrant()
			if err != nil {
				t.Fatal(err)
			}
			grant.ResourceScopes[0].GetSelector().ResourceIds["group"] = "changed"
			again, err := admission.CapabilityGrant()
			if err != nil || proto.Equal(grant, again) {
				t.Fatal("consumer mutation changed the actual authority grant")
			}
			_, err = a.Authorize(ctx, AccessRequest{Backend: regressionBackend, Operation: "write", Scopes: []*wire.ResourceScope{regressionScope("group", "a")}})
			regressionError(t, err, codes.FailedPrecondition, "OPERATION_ALREADY_ADMITTED")
		})
	}
}

func TestAwaitOperationSTARTGateDoesNotCreateAuthority(t *testing.T) {
	for _, outcome := range []string{"running", "caller-canceled", "failed"} {
		t.Run(outcome, func(t *testing.T) {
			i := regressionInstance(t, regressionManager(), "owner")
			i.state, i.activating = Ready, true
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			bound := regressionRPC(t, i, parent)
			ctx := &regressionGateContext{Context: bound, waiting: make(chan struct{})}
			var p InstancePrincipal
			var err error
			done := make(chan struct{})
			go func() {
				p, err = (&Authorizer{instance: i}).AwaitOperation(ctx, regressionBackend, "write")
				close(done)
			}()
			regressionWait(t, ctx.waiting)
			i.mu.Lock()
			if len(i.admissions) != 0 || i.controls != 1 {
				i.mu.Unlock()
				t.Fatal("readonly gate wait reserved authority or another control slot")
			}
			select {
			case <-done:
				i.mu.Unlock()
				t.Fatal("START gate returned before transition")
			default:
			}
			switch outcome {
			case "running":
				i.state = Running
				i.openGateLocked()
				// This races both wake signals just as successful START does.
				i.cancelStartup()
			case "failed":
				i.failLocked("START_FAILED")
			case "caller-canceled":
				cancel()
			}
			i.mu.Unlock()
			regressionWait(t, done)
			if outcome == "running" {
				if err != nil || p != i.principal {
					t.Fatalf("committed START not observed: %v %v", p, err)
				}
			} else if err == nil {
				t.Fatal("unsuccessful START wait returned a principal")
			}
			if outcome == "caller-canceled" {
				regressionError(t, err, codes.Canceled, "context canceled")
			}
			if len(i.admissions) != 0 {
				t.Fatal("AwaitOperation created an authority lease")
			}
			if _, err := AdmissionFromContext(bound); err == nil {
				t.Fatal("readonly preflight can be reused as mutation authority")
			}
			if outcome == "running" {
				// Eligibility is rechecked; a successful lookup is no lease on
				// RUNNING if lifecycle changes before final target resolution.
				i.state = Draining
				_, err = (&Authorizer{instance: i}).Authorize(bound, AccessRequest{Backend: regressionBackend, Operation: "write", Scopes: []*wire.ResourceScope{regressionScope("group", "a")}})
				regressionError(t, err, codes.FailedPrecondition, "INSTANCE_DRAINING")
			}
		})
	}
}

func TestDrainRequiresActiveWorkReference(t *testing.T) {
	for _, tc := range []struct {
		name                                                                                            string
		refs                                                                                            []string
		expiredWork, expiredDrain, cleanup, longLived, notDrainSafe, foreignWork, foreignScope, allowed bool
	}{
		{name: "active", refs: []string{"active"}, allowed: true},
		{name: "unknown", refs: []string{"unknown"}},
		{name: "foreign-active", refs: []string{"foreign-active"}, foreignWork: true},
		{name: "missing"},
		{name: "ambiguous", refs: []string{"active", "active"}},
		{name: "completed-callback", refs: []string{"active"}, expiredWork: true},
		{name: "expired-drain", refs: []string{"active"}, expiredDrain: true},
		{name: "long-lived", refs: []string{"active"}, longLived: true},
		{name: "not-drain-safe", refs: []string{"active"}, notDrainSafe: true},
		{name: "owner-cleanup", cleanup: true, allowed: true},
		{name: "owner-cleanup-foreign-scope", cleanup: true, foreignScope: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := regressionManager()
			i := regressionInstance(t, m, "owner")
			i.state = Draining
			i.drain, i.cancelDrain = context.WithCancel(context.Background())
			defer i.cancelDrain()
			work, cancelWork := context.WithCancel(context.Background())
			defer cancelWork()
			i.workRef, i.workContext = "active", work
			if tc.foreignWork {
				other := regressionInstance(t, m, "other")
				other.workRef, other.workContext = "foreign-active", work
			}
			if tc.expiredWork {
				cancelWork()
			}
			if tc.expiredDrain {
				i.cancelDrain()
			}
			policy := m.operations[operationKey(regressionBackend, "write")]
			if tc.cleanup {
				policy.Class = OwnerCleanupOperation
				policy.DrainSafe = false
			}
			if tc.longLived {
				policy.Class = LongLivedOperation
				policy.DrainSafe = false
			}
			if tc.notDrainSafe {
				policy.DrainSafe = false
			}
			m.operations[operationKey(regressionBackend, "write")] = policy
			md := metadata.Pairs("module-id", "forged", "instance-id", "forged")
			md[core.WorkRefMetadata] = tc.refs
			ctx := regressionRPC(t, i, metadata.NewIncomingContext(context.Background(), md))
			scopes := []*wire.ResourceScope{regressionScope("group", "a")}
			if tc.foreignScope {
				scopes = []*wire.ResourceScope{regressionScope("group", "foreign")}
			}
			p, err := (&Authorizer{instance: i}).Authorize(ctx, AccessRequest{Backend: regressionBackend, Operation: "write", Scopes: scopes})
			if !tc.allowed {
				if tc.foreignScope {
					regressionError(t, err, codes.PermissionDenied, "RESOURCE_SCOPE_DENIED")
				} else {
					regressionError(t, err, codes.FailedPrecondition, "INSTANCE_DRAINING")
				}
				if len(i.admissions) != 0 {
					t.Fatal("denied DRAIN work created a lease")
				}
				return
			}
			if err != nil || p != i.principal {
				t.Fatalf("DRAIN principal=%v err=%v", p, err)
			}
			if !tc.cleanup {
				lease, err := AdmissionFromContext(ctx)
				if err != nil {
					t.Fatal(err)
				}
				cancelWork()
				regressionWait(t, lease.Context().Done())
				if _, err := lease.CapabilityGrant(); err == nil {
					t.Fatal("completed event retained authority")
				}
			}
		})
	}
}

func TestMetadataCannotAuthenticateAnInstance(t *testing.T) {
	i := regressionInstance(t, regressionManager(), "owner")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("module-id", string(i.principal.ModuleID), "instance-id", string(i.principal.InstanceID), core.WorkRefMetadata, "active"))
	if _, err := PrincipalFromContext(ctx); err == nil {
		t.Fatal("metadata authenticated a principal")
	}
	_, err := (&Authorizer{instance: i}).AwaitOperation(ctx, regressionBackend, "write")
	regressionError(t, err, codes.Unauthenticated, "UNAUTHENTICATED_INSTANCE")
	_, err = (&Authorizer{instance: i}).Authorize(ctx, AccessRequest{Backend: regressionBackend, Operation: "write", Scopes: []*wire.ResourceScope{regressionScope("group", "a")}})
	regressionError(t, err, codes.Unauthenticated, "UNAUTHENTICATED_INSTANCE")
	other := regressionInstance(t, i.manager, "other")
	bound := regressionRPC(t, other, ctx)
	_, err = (&Authorizer{instance: i}).Authorize(bound, AccessRequest{Backend: regressionBackend, Operation: "write", Scopes: []*wire.ResourceScope{regressionScope("group", "a")}})
	regressionError(t, err, codes.Unauthenticated, "UNAUTHENTICATED_INSTANCE")
}

func TestPrimaryBrokerFailureRevokesOnlyItsInstance(t *testing.T) {
	for _, state := range []RuntimeState{Starting, Running} {
		for _, malformed := range []bool{true, false} {
			reason := "BROKER_TRANSPORT_LOST"
			if malformed {
				reason = "BROKER_PROTOCOL_VIOLATION"
			}
			t.Run(string(state)+"/"+reason, func(t *testing.T) {
				m := regressionManager()
				victim := regressionInstance(t, m, "victim")
				peer := regressionInstance(t, m, "peer")
				peerRPC := regressionAdmittedRPC(t, peer)
				peerLease, err := AdmissionFromContext(peerRPC)
				if err != nil {
					t.Fatal(err)
				}
				victim.state, victim.bound = Starting, false
				// This fixture owns teardown; the callback still executes the
				// production failure transition and lifetime cancellation.
				victim.stopStarted = true
				guard, err := victim.newBrokerGuard()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(guard.Close)
				var victimLease *Admission
				if state == Running {
					victim.state, victim.bound = Running, true
					victimRPC := regressionAdmittedRPC(t, victim)
					victimLease, err = AdmissionFromContext(victimRPC)
					if err != nil {
						t.Fatal(err)
					}
				}
				conn, incoming := regressionBrokerConnection(t, guard, malformed)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, "/plugin.GRPCBroker/StartStream")
				if err != nil {
					t.Fatal(err)
				}
				err = stream.RecvMsg(incoming)
				expectedCode := codes.Unavailable
				if malformed {
					expectedCode = codes.FailedPrecondition
				}
				if statusCode := status.Code(err); statusCode != expectedCode {
					t.Fatalf("primary broker receive=%v; want %s", err, expectedCode)
				}
				snapshot := victim.Snapshot()
				if snapshot.State != Failed || snapshot.FailureReason != reason {
					t.Fatalf("primary connection failure did not fail its instance: %+v", snapshot)
				}
				regressionWait(t, victim.lifetime.Done())
				regressionWait(t, victim.startup.Done())
				if victimLease != nil {
					regressionWait(t, victimLease.Context().Done())
					if _, err := victimLease.CapabilityGrant(); err == nil {
						t.Fatal("compromised primary connection retained operation authority")
					}
				}
				_, _, err = victim.beginRPC(context.Background())
				regressionError(t, err, codes.Unauthenticated, "UNAUTHENTICATED_INSTANCE")
				peerSnapshot := peer.Snapshot()
				if peerSnapshot.State != Running || peerSnapshot.FailureReason != "" || peer.lifetime.Err() != nil {
					t.Fatalf("one primary failure damaged another instance: %+v", peerSnapshot)
				}
				if _, err := peerLease.CapabilityGrant(); err != nil {
					t.Fatalf("peer operation authority was revoked: %v", err)
				}
				principal, err := PrincipalFromContext(peerRPC)
				if err != nil || principal != peer.principal {
					t.Fatalf("peer identity changed: %v %v", principal, err)
				}
			})
		}
	}
}
