package runtime

import (
	"context"
	"slices"
	"strings"

	"github.com/thirdscam/chatanium/internal/discordacl"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/grpc/codes"
)

const discordBackend = "discord"

func (m *Manager) setInitialDiscordACL(policies map[ModuleID]discordacl.Policy) error {
	m.discordACL = make(map[ModuleID]*discordacl.Policy, len(policies))
	for id, policy := range policies {
		if _, ok := m.installed[id]; !ok {
			return ErrModuleNotInstalled
		}
		if err := policy.Validate(); err != nil {
			return invalidConfig()
		}
		m.discordACL[id] = &discordacl.Policy{Scopes: slices.Clone(policy.Scopes)}
	}
	return nil
}

// SetDiscordACL replaces the policy for this module, without changing its
// negotiated grants. It also sets the policy used on subsequent launches.
func (m *Manager) SetDiscordACL(ctx context.Context, moduleID string, policy discordacl.Policy) error {
	if ctx == nil || policy.Validate() != nil {
		return invalidConfig()
	}
	next := &discordacl.Policy{Scopes: slices.Clone(policy.Scopes)}
	id := ModuleID(moduleID)
	var waitingOn *Instance
	for {
		m.mu.Lock()
		if _, ok := m.installed[id]; !ok {
			m.mu.Unlock()
			return ErrModuleNotInstalled
		}
		i := m.instances[id]
		if i != nil {
			i.mu.Lock()
		}
		if ctx.Err() != nil {
			if i != nil {
				i.mu.Unlock()
			}
			m.mu.Unlock()
			return contextError(ctx)
		}
		// A legacy native voice job can outlive its RPC. Never claim to
		// have fenced such a running instance with a newly managed policy.
		if i != nil && i.discordACL == nil && !i.cleanupComplete && i.hasNativeVoiceGrantLocked() {
			i.mu.Unlock()
			m.mu.Unlock()
			return runtimeError(codes.FailedPrecondition, "DISCORD_NATIVE_VOICE_REQUIRES_RESTART")
		}
		// No stale callback can be scheduled after success. If the event lane
		// already owns a now-denied event, let that callback finish without
		// cancellation (a canceled hook would fail an otherwise healthy module).
		if i != nil && i.discordWork.discord && !discordAllows(next, i.discordWork.discordScopes) {
			if waitingOn != i {
				waitingOn = i
				i.discordACLWaiters++
				defer func() {
					i.mu.Lock()
					i.discordACLWaiters--
					i.signalLocked()
					i.mu.Unlock()
				}()
			}
			changed := i.changed
			i.mu.Unlock()
			m.mu.Unlock()
			select {
			case <-ctx.Done():
				return contextError(ctx)
			case <-changed:
			}
			continue
		}
		m.discordACL[id] = next
		if i != nil {
			i.discordACL = next
			i.discardRevokedDiscordEventsLocked()
			for admission := range i.admissions {
				if admission.policy.Backend == discordBackend && !discordAllows(next, admission.discordScopes) {
					admission.cancel()
				}
			}
			i.mu.Unlock()
		}
		m.mu.Unlock()
		return nil
	}
}

func discordScope(scope *wire.ResourceScope) discordacl.Scope {
	return discordSelectorScope(scope.GetSelector())
}

func discordSelectorScope(selector *wire.ResourceSelector) discordacl.Scope {
	ids := selector.GetResourceIds()
	return discordacl.Scope{GuildID: ids["guild_id"], ChannelID: ids["channel_id"]}
}

func discordAllows(policy *discordacl.Policy, scopes []discordacl.Scope) bool {
	if policy == nil {
		return true
	}
	if len(scopes) == 0 {
		return false
	}
	for _, scope := range scopes {
		if !policy.Allows(scope) {
			return false
		}
	}
	return true
}

func isDiscordNativeVoice(capability string) bool {
	return strings.HasPrefix(capability, "discord.voice.")
}

func (i *Instance) hasNativeVoiceGrantLocked() bool {
	if i.grants == nil {
		return false
	}
	grant := backendGrant(i.grants, discordBackend)
	if grant == nil {
		return false
	}
	for _, capability := range grant.Capabilities {
		if isDiscordNativeVoice(capability.GetName()) {
			return true
		}
	}
	return false
}

func (a *Authorizer) ManagedDiscordACL() bool {
	i := a.instance
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.discordACL != nil
}

// CheckDiscordResult applies the current limit to the complete, trusted set of
// resources a Discord response will project.
func (a *Admission) CheckDiscordResult(scopes []discordacl.Scope) error {
	i := a.instance
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.discordACL != nil && (!a.validLocked() || !discordAllows(i.discordACL, scopes)) {
		return runtimeError(codes.PermissionDenied, "RESOURCE_SCOPE_DENIED")
	}
	return nil
}

func (i *Instance) discardRevokedDiscordEventsLocked() {
	kept := i.queue[:0]
	for _, event := range i.queue {
		if event.discord && !discordAllows(i.discordACL, event.discordScopes) {
			i.retainedCount--
			i.retainedBytes -= int64(len(event.raw))
			continue
		}
		kept = append(kept, event)
	}
	clear(i.queue[len(kept):])
	i.queue = kept
}
