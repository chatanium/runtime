package runtime

import (
	"context"
	"errors"
	"testing"
	"time"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// A backend-private key, not a token, exercises the real registry and leases.
type regressionCredentialKey struct{ id int }

func (*regressionCredentialKey) BackendCredentialHandle() {}

func regressionCredential(t *testing.T, i *Instance) (*wire.CredentialRef, CredentialRequirement, *regressionCredentialKey) {
	t.Helper()
	resource := regressionScope("group", "a").GetSelector()
	key := &regressionCredentialKey{id: 1}
	ref, err := i.manager.credentials.Issue(context.Background(), i.principal, CredentialBinding{
		BackendID: regressionBackend, Purpose: "respond", Resource: resource,
		ExpiresAt: time.Now().Add(30 * time.Minute), BackendHandle: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ref, CredentialRequirement{BackendID: regressionBackend, Purpose: "respond", Resource: resource}, key
}

func regressionAdmittedRPC(t *testing.T, i *Instance) context.Context {
	t.Helper()
	ctx := regressionRPC(t, i, context.Background())
	_, err := (&Authorizer{instance: i}).Authorize(ctx, AccessRequest{Backend: regressionBackend, Operation: "write", Scopes: []*wire.ResourceScope{regressionScope("group", "a")}})
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func TestCredentialRequiresOwnerAdmissionAndExactBinding(t *testing.T) {
	m := regressionManager()
	i := regressionInstance(t, m, "owner")
	other := regressionInstance(t, m, "other")
	ref, want, key := regressionCredential(t, i)
	ctx := regressionAdmittedRPC(t, i)
	for _, tc := range []struct {
		name       string
		changeRef  func(*wire.CredentialRef)
		changeWant func(*CredentialRequirement)
	}{
		{name: "opaque-id", changeRef: func(r *wire.CredentialRef) { r.OpaqueId += "forged" }},
		{name: "backend-metadata", changeRef: func(r *wire.CredentialRef) { r.BackendId = "other" }},
		{name: "purpose-metadata", changeRef: func(r *wire.CredentialRef) { r.Purpose = "other" }},
		{name: "scope-metadata", changeRef: func(r *wire.CredentialRef) { r.ResourceScope.ResourceIds["group"] = "b" }},
		{name: "expiry-metadata", changeRef: func(r *wire.CredentialRef) { r.ExpiresAt.Seconds++ }},
		{name: "backend-requirement", changeWant: func(w *CredentialRequirement) { w.BackendID = "other" }},
		{name: "purpose-requirement", changeWant: func(w *CredentialRequirement) { w.Purpose = "other" }},
		{name: "scope-requirement", changeWant: func(w *CredentialRequirement) { w.Resource = regressionScope("group", "b").GetSelector() }},
		{name: "narrower-is-not-exact", changeWant: func(w *CredentialRequirement) { w.Resource.ResourceIds["item"] = "one" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := proto.Clone(ref).(*wire.CredentialRef)
			requirement := want
			requirement.Resource = proto.Clone(want.Resource).(*wire.ResourceSelector)
			if tc.changeRef != nil {
				tc.changeRef(candidate)
			}
			if tc.changeWant != nil {
				tc.changeWant(&requirement)
			}
			lease, err := m.credentials.Acquire(ctx, candidate, requirement)
			regressionError(t, err, codes.PermissionDenied, "CREDENTIAL_REFERENCE_INVALID")
			if lease != nil || len(i.credentials[ref.OpaqueId].leases) != 0 {
				t.Fatal("invalid binding reserved a credential lease")
			}
		})
	}
	_, err := m.credentials.Acquire(regressionAdmittedRPC(t, other), ref, want)
	regressionError(t, err, codes.PermissionDenied, "CREDENTIAL_REFERENCE_INVALID")
	_, err = m.credentials.Acquire(regressionRPC(t, i, context.Background()), ref, want)
	regressionError(t, err, codes.PermissionDenied, "REQUIRED_CAPABILITY_DENIED")
	lease, err := m.credentials.Acquire(ctx, ref, want)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	got, err := lease.Handle()
	if err != nil || got != key {
		t.Fatalf("backend handle=%v err=%v", got, err)
	}
	_, err = m.credentials.Acquire(ctx, ref, want)
	regressionError(t, err, codes.ResourceExhausted, "CREDENTIAL_LEASE_ALREADY_ACQUIRED")
	// Issue and returned references must not alias the trusted stored binding.
	canonical := proto.Clone(ref).(*wire.CredentialRef)
	ref.Purpose = "caller-mutated"
	second, err := m.credentials.Acquire(regressionAdmittedRPC(t, i), canonical, want)
	if err != nil {
		t.Fatalf("wire mutation changed the stored credential binding: %v", err)
	}
	second.Release()
	lease.Release()
	regressionWait(t, lease.Context().Done())
	if _, err := lease.Handle(); err == nil {
		t.Fatal("released lease revealed its backend handle")
	}
}

func TestCredentialRejectsStaleOwnerAndExpiredReference(t *testing.T) {
	m := regressionManager()
	i := regressionInstance(t, m, "owner")
	ref, want, key := regressionCredential(t, i)
	binding := CredentialBinding{BackendID: regressionBackend, Purpose: want.Purpose, Resource: want.Resource, ExpiresAt: time.Now().Add(time.Hour), BackendHandle: key}
	stale := i.principal
	stale.InstanceID = "previous-instance"
	if _, err := m.credentials.Issue(context.Background(), stale, binding); err == nil {
		t.Fatal("stale instance issued a reference")
	}
	binding.ExpiresAt = time.Unix(1, 0)
	if _, err := m.credentials.Issue(context.Background(), i.principal, binding); err == nil {
		t.Fatal("already expired binding was issued")
	}
	// Seed an elapsed stored deadline without sleeps or a fake production clock.
	// Both wire metadata and stored metadata agree: rejection must be expiry,
	// not the tampered-reference comparison tested above.
	i.mu.Lock()
	r := i.credentials[ref.OpaqueId]
	r.timer.Stop()
	r.ref.ExpiresAt = timestamppb.New(time.Unix(1, 0))
	expired := proto.Clone(r.ref).(*wire.CredentialRef)
	i.mu.Unlock()
	_, err := m.credentials.Acquire(regressionAdmittedRPC(t, i), expired, want)
	regressionError(t, err, codes.PermissionDenied, "CREDENTIAL_REFERENCE_INVALID")
	if len(r.leases) != 0 {
		t.Fatal("expired reference reserved a lease")
	}
}

func TestCredentialLeaseTracksAdmissionAndInstanceRevocation(t *testing.T) {
	for _, end := range []string{"admission", "instance"} {
		t.Run(end, func(t *testing.T) {
			m := regressionManager()
			i := regressionInstance(t, m, "owner")
			ref, want, _ := regressionCredential(t, i)
			ctx := regressionAdmittedRPC(t, i)
			lease, err := m.credentials.Acquire(ctx, ref, want)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			r := i.credentials[ref.OpaqueId]
			var revokeDone chan struct{}
			var revokeErr error
			if end == "admission" {
				admission, err := AdmissionFromContext(ctx)
				if err != nil {
					t.Fatal(err)
				}
				admission.Release()
			} else {
				bounded, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				revokeDone = make(chan struct{})
				go func() { revokeErr = m.credentials.RevokeInstance(bounded, i.principal); close(revokeDone) }()
			}
			regressionWait(t, lease.Context().Done())
			if _, err := lease.Handle(); err == nil {
				t.Fatal("canceled lease revealed its handle")
			}
			if end == "instance" {
				// Cancellation forbids use immediately, but physical ownership is
				// retained until the backend releases its outstanding lease.
				select {
				case <-revokeDone:
					t.Fatal("instance revocation completed before lease release")
				default:
				}
				i.mu.Lock()
				retained := i.credentials[ref.OpaqueId] == r && r.handle != nil && r.revoked
				i.mu.Unlock()
				if !retained {
					t.Fatal("revocation discarded outstanding backend ownership")
				}
				_, err := m.credentials.Acquire(regressionAdmittedRPC(t, i), ref, want)
				regressionError(t, err, codes.PermissionDenied, "CREDENTIAL_REFERENCE_INVALID")
			}
			lease.Release()
			if revokeDone != nil {
				regressionWait(t, revokeDone)
				if revokeErr != nil {
					t.Fatal(revokeErr)
				}
				i.mu.Lock()
				remaining, handle := len(i.credentials), r.handle
				i.mu.Unlock()
				if remaining != 0 || handle != nil {
					t.Fatal("released revoked credential was not reclaimed")
				}
			}
		})
	}
}

// Registration can own a real credential lease before Prepare, including when
// Register ultimately fails. The unused phases fail closed in this fixture.
type regressionCredentialOwner struct {
	lease      *CredentialLease
	cleanupErr error
}

func (*regressionCredentialOwner) Prepare(context.Context, InstancePrincipal, BackendPreparation) (*BackendBinding, error) {
	return nil, errors.New("unexpected Prepare")
}
func (*regressionCredentialOwner) Activate(context.Context, InstancePrincipal) error {
	return errors.New("unexpected Activate")
}
func (*regressionCredentialOwner) Drain(context.Context, InstancePrincipal) error {
	return errors.New("unexpected Drain")
}
func (o *regressionCredentialOwner) Cleanup(context.Context, InstancePrincipal) error {
	if o.lease != nil {
		o.lease.Release()
	}
	return o.cleanupErr
}

func TestRegisteredBackendCleanupReleasesUnpreparedAndPartialOwners(t *testing.T) {
	m := regressionManager()
	i := regressionInstance(t, m, "owner")
	ref, want, _ := regressionCredential(t, i)
	cleanupErr := errors.New("first owner cleanup failed")
	registerErr := errors.New("second owner registration failed after acquiring")
	owners := []*regressionCredentialOwner{{cleanupErr: cleanupErr}, {}}
	for n, owner := range owners {
		ctx := regressionAdmittedRPC(t, i)
		registration := BackendRegistration{
			ID: regressionBackend, Adapter: owner,
			Register: func(services InstanceServices) (core.HelperRegistrar, error) {
				lease, err := services.Credentials.Acquire(ctx, ref, want)
				if err != nil {
					return nil, err
				}
				owner.lease = lease
				if n == 1 {
					return nil, registerErr
				}
				return nil, nil
			},
		}
		_, err := i.registerBackend(registration, InstanceServices{Principal: i.principal, Authorizer: &Authorizer{instance: i}, Credentials: m.credentials})
		if n == 0 && err != nil {
			t.Fatal(err)
		}
		if n == 1 && !errors.Is(err, registerErr) {
			t.Fatalf("partial registration: %v", err)
		}
		if owner.lease == nil {
			t.Fatal("registration did not acquire its resource")
		}
		defer owner.lease.Release()
		if _, err := owner.lease.Handle(); err != nil {
			t.Fatal(err)
		}
	}
	if len(i.prepared) != 0 {
		t.Fatal("fixture unexpectedly prepared a backend")
	}
	for range 2 {
		err := i.cleanupRegisteredBackends(context.Background())
		if !errors.Is(err, cleanupErr) {
			t.Fatalf("cleanup discarded the first owner's error: %v", err)
		}
		for _, owner := range owners {
			regressionWait(t, owner.lease.Context().Done())
			if _, err := owner.lease.Handle(); err == nil {
				t.Fatal("registered owner retained a credential after cleanup")
			}
		}
	}
	bounded, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.credentials.RevokeInstance(bounded, i.principal); err != nil {
		t.Fatalf("registered owner blocked final credential reclamation: %v", err)
	}
	if len(i.credentials) != 0 {
		t.Fatal("released registration resources remained retained")
	}
}
