package runtime

import (
	"context"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/thirdscam/chatanium/internal/discordacl"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// BackendEvent contains trusted resolved resource facts and a credential-safe
// projector. Project must be bounded, in-process and must not invoke modules or
// perform remote lookups. Only registered typed events may reach this entrypoint.
// Recipient applies backend-owned route/command ownership before projection.
type EventPolicy struct {
	EventType      string
	Operation      string
	PayloadTypeURL string
}
type BackendEvent struct {
	BackendID    string
	BackendMajor uint32
	EventType    string
	Operation    string
	Scope        *wire.ResourceScope
	ReceivedAt   time.Time
	Recipient    func(InstancePrincipal) bool
	Project      func(context.Context, InstancePrincipal) (*anypb.Any, error)
	// DiscordScopes is host-verified evidence covering the projected event,
	// including nested resources. An empty list means it cannot be scoped.
	DiscordScopes []discordacl.Scope
}
type queuedEvent struct {
	raw           []byte
	discord       bool
	discordScopes []discordacl.Scope
}
type Dispatcher struct {
	mu       sync.Mutex
	manager  *Manager
	sequence uint64
}

func (d *Dispatcher) Admit(ctx context.Context, event BackendEvent) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	m := d.manager
	b, ok := m.backends[event.BackendID]
	policy, registered := m.operations[operationKey(event.BackendID, event.Operation)]
	registeredEvent, eventKnown := m.events[operationKey(event.BackendID, event.EventType)]
	if !ok || b.Major != event.BackendMajor || !registered || !eventKnown || registeredEvent.Operation != event.Operation || event.EventType == "" || event.Project == nil || event.ReceivedAt.IsZero() || !timestamppb.New(event.ReceivedAt).IsValid() || !validScope(event.Scope, policy.ResourceFree) || event.Scope.GetAllResources() || b.ValidateSelector(event.Scope.GetSelector()) != nil {
		return runtimeError(codes.InvalidArgument, "BACKEND_DISPATCH_INVALID")
	}
	if ctx.Err() != nil {
		return contextError(ctx)
	}
	if d.sequence == math.MaxUint64 {
		return runtimeError(codes.ResourceExhausted, "INGRESS_SEQUENCE_EXHAUSTED")
	}
	d.sequence++
	discord := event.BackendID == discordBackend
	var discordScopes []discordacl.Scope
	for moduleID := range m.installed {
		m.mu.Lock()
		i := m.instances[moduleID]
		m.mu.Unlock()
		if i == nil {
			continue
		}
		i.mu.Lock()
		eligible := i.state == Running && i.bound && eventAllowedLocked(i, policy, event.Scope) && (!discord || discordAllows(i.discordACL, event.DiscordScopes))
		i.mu.Unlock()
		if !eligible || event.Recipient != nil && !event.Recipient(i.principal) {
			continue
		}
		payload, err := event.Project(ctx, i.principal)
		if err != nil || payload == nil || payload.TypeUrl != registeredEvent.PayloadTypeURL {
			i.mu.Lock()
			// Preserve the unmanaged failure policy. For a managed instance
			// a newly revoked event is no longer its failure to own.
			failed := (!discord || discordAllows(i.discordACL, event.DiscordScopes)) && i.failLocked("EVENT_PROJECTION_FAILED")
			i.mu.Unlock()
			if failed {
				m.startStop(i, nil)
			}
			continue
		}
		envelope := &wire.EventEnvelope{BackendId: event.BackendID, BackendMajor: event.BackendMajor, EventType: event.EventType, IngressSequence: d.sequence, ReceivedAt: timestamppb.New(event.ReceivedAt), Payload: payload}
		size := proto.Size(envelope)
		i.mu.Lock()
		// Projection ran outside the instance lock. Recheck before reserving
		// room in the queue.
		if i.state != Running || !i.bound || !eventAllowedLocked(i, policy, event.Scope) || discord && !discordAllows(i.discordACL, event.DiscordScopes) {
			i.mu.Unlock()
			continue
		}
		limits := m.config.Defaults
		if i.retainedCount >= limits.EventQueueEvents || int64(size) > limits.EventQueueBytes-i.retainedBytes || size > m.config.Limits.ControlMessageMaxBytes {
			i.failLocked("EVENT_QUEUE_OVERFLOW")
			i.mu.Unlock()
			m.startStop(i, nil)
			continue
		}
		raw, err := proto.Marshal(envelope)
		if err != nil {
			i.mu.Unlock()
			m.fail(i, "EVENT_PROJECTION_FAILED")
			continue
		}
		if discordScopes == nil && len(event.DiscordScopes) != 0 {
			discordScopes = slices.Clone(event.DiscordScopes)
		}
		i.queue = append(i.queue, queuedEvent{raw: raw, discord: discord, discordScopes: discordScopes})
		i.retainedCount++
		i.retainedBytes += int64(len(raw))
		i.signalLocked()
		i.mu.Unlock()
	}
	return nil
}
func eventAllowedLocked(i *Instance, p OperationPolicy, scope *wire.ResourceScope) bool {
	b := backendGrant(i.grants, p.Backend)
	if b == nil {
		return false
	}
	cap := capability(b.Capabilities, p.Capability)
	if cap == nil {
		return false
	}
	for _, s := range cap.ResourceScopes {
		if scopeContains(s, scope) {
			return true
		}
	}
	return false
}
func (i *Instance) eventLane() {
	defer close(i.laneDone)
	for {
		i.mu.Lock()
		if i.state == Failed || i.state == Stopped {
			i.mu.Unlock()
			return
		}
		parent := i.lifetime
		if i.state == Draining {
			parent = i.drain
			if parent.Err() != nil {
				i.mu.Unlock()
				return
			}
			if !i.drainSent {
				ready := i.drainReady
				i.mu.Unlock()
				select {
				case <-parent.Done():
					return
				case <-ready:
				}
				i.mu.Lock()
				if i.state != Draining || parent.Err() != nil {
					i.mu.Unlock()
					return
				}
				i.callbackActive = true
				i.mu.Unlock()
				err := i.manager.stage(parent, i, wire.Stage_STAGE_DRAIN, nil)
				i.mu.Lock()
				if err == nil {
					i.callbackActive = false
					i.drainSent = true
					i.signalLocked()
				}
				i.mu.Unlock()
				if err != nil {
					i.manager.fail(i, "HOOK_FAILED")
					return
				}
				continue
			}
		}
		if len(i.queue) == 0 {
			if i.state == Draining {
				i.mu.Unlock()
				return
			}
			changed := i.changed
			i.mu.Unlock()
			select {
			case <-i.lifetime.Done():
				return
			case <-changed:
			}
			continue
		}
		if i.discordACLWaiters != 0 && i.queue[0].discord {
			changed := i.changed
			i.mu.Unlock()
			select {
			case <-parent.Done():
				return
			case <-changed:
			}
			continue
		}
		event := i.queue[0]
		i.queue[0] = queuedEvent{}
		i.queue = i.queue[1:]
		if event.discord && !discordAllows(i.discordACL, event.discordScopes) {
			i.retainedCount--
			i.retainedBytes -= int64(len(event.raw))
			i.mu.Unlock()
			continue
		}
		ref, err := randomID()
		if err != nil {
			i.mu.Unlock()
			i.manager.fail(i, "EVENT_WORK_REFERENCE_FAILED")
			return
		}
		callback, cancel := context.WithTimeout(parent, time.Duration(i.manager.config.Limits.HookRPCDeadline))
		callback = metadata.NewOutgoingContext(callback, metadata.Pairs(core.WorkRefMetadata, ref))
		i.workRef = ref
		i.workContext = callback
		i.callbackActive = true
		if event.discord {
			i.discordWork = event
		}
		i.mu.Unlock()
		envelope := new(wire.EventEnvelope)
		err = proto.Unmarshal(event.raw, envelope)
		if err == nil {
			err = i.hooks.OnEvent(callback, envelope)
		}
		cancel()
		i.mu.Lock()
		i.workRef = ""
		i.workContext = nil
		i.discordWork = queuedEvent{}
		if err == nil {
			i.callbackActive = false
			i.retainedCount--
			i.retainedBytes -= int64(len(event.raw))
			i.signalLocked()
		}
		i.mu.Unlock()
		if err != nil {
			reason := "HOOK_FAILED"
			if callback.Err() == context.DeadlineExceeded {
				reason = "HOOK_DEADLINE_EXCEEDED"
			}
			i.manager.fail(i, reason)
			return
		}
	}
}

// FailEvent handles a known malformed event for which trustworthy target facts
// cannot be recovered. It never fabricates a scope, projects a payload, issues
// credentials or queues an event. Only RUNNING holders of that registered
// event's actual capability that do not require a verified Discord scope are failed.
// reason must be a fixed trusted code, never source JSON or an error body.
func (d *Dispatcher) FailEvent(ctx context.Context, backend, eventType, reason string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	m := d.manager
	registration, backendKnown := m.backends[backend]
	event, eventKnown := m.events[operationKey(backend, eventType)]
	policy, operationKnown := m.operations[operationKey(backend, event.Operation)]
	if !backendKnown || !eventKnown || !operationKnown || policy.Backend != registration.ID || policy.Capability == "" || !validBackendFailureReason(reason, m.config.Limits.ControlMessageMaxBytes) {
		return runtimeError(codes.InvalidArgument, "BACKEND_DISPATCH_INVALID")
	}
	if ctx.Err() != nil {
		return contextError(ctx)
	}
	d.failBackendInstancesLocked(backend, reason, policy.Capability)
	return nil
}

// FailBackend is reserved for an unattributable fatal backend decode or state
// integrity fault, not an ordinary API failure or an unowned route. It fails
// actual and preparing participants, without making core-only modules depend
// on every backend whose helper services were merely pre-registered.
func (d *Dispatcher) FailBackend(ctx context.Context, backend, reason string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	m := d.manager
	if _, known := m.backends[backend]; !known || !validBackendFailureReason(reason, m.config.Limits.ControlMessageMaxBytes) {
		return runtimeError(codes.InvalidArgument, "BACKEND_DISPATCH_INVALID")
	}
	if ctx.Err() != nil {
		return contextError(ctx)
	}
	d.failBackendInstancesLocked(backend, reason, "")
	return nil
}

// d.mu serializes failure admission with event admission. Each failure is
// committed under the same instance lock as authority/queue state; cleanup is
// scheduled outside it and never awaited by backend ingress.
func (d *Dispatcher) failBackendInstancesLocked(backend, reason, eventCapability string) {
	m := d.manager
	for moduleID := range m.installed {
		m.mu.Lock()
		instance := m.instances[moduleID]
		m.mu.Unlock()
		if instance == nil {
			continue
		}
		instance.mu.Lock()
		var actual *wire.BackendGrant
		if instance.grants != nil {
			actual = backendGrant(instance.grants, backend)
		}
		eligible := false
		if eventCapability != "" {
			if instance.state == Running && instance.bound && actual != nil && (backend != discordBackend || instance.discordACL == nil) {
				grant := capability(actual.Capabilities, eventCapability)
				eligible = grant != nil && len(grant.ResourceScopes) != 0
			}
		} else {
			eligible = actual != nil
			if !eligible {
				for _, prepared := range instance.prepared {
					if prepared.ID == backend {
						eligible = true
						break
					}
				}
			}
		}
		failed := eligible && instance.failLocked(reason)
		instance.mu.Unlock()
		if failed {
			m.startStop(instance, nil)
		}
	}
}

func validBackendFailureReason(reason string, maxBytes int) bool {
	if len(reason) == 0 || len(reason) > maxBytes || reason[0] < 'A' || reason[0] > 'Z' {
		return false
	}
	for _, character := range reason {
		if character != '_' && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}
