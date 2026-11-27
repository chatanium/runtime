package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/thirdscam/chatanium/internal/discordacl"
	"github.com/thirdscam/chatanium/internal/discordsetup"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/portable/session"
	"github.com/thirdscam/chatanium/internal/portable/store"
	modruntime "github.com/thirdscam/chatanium/internal/runtime"
	"google.golang.org/protobuf/proto"
)

type aclReview struct {
	status discordacl.Status
	token  string
}

type aclModule struct {
	binding string
	status  discordacl.Status
	review  aclReview
}

type aclOwner struct {
	mu              sync.Mutex
	modules         map[string]aclModule
	db              *store.Store
	epoch, revision string
	token           string
	worker          chan workerACLRequest
	life            context.Context
	fenceWorker     context.CancelFunc
	sequence        uint64
}

func loadACL(ctx context.Context, db *store.Store, config modruntime.Config, epoch, revision, token string, life context.Context, fenceWorker context.CancelFunc) (*aclOwner, error) {
	stored, err := db.DiscordACLs(ctx)
	if err != nil {
		return nil, err
	}
	a := &aclOwner{modules: make(map[string]aclModule), db: db, epoch: epoch, revision: revision, token: token,
		worker: make(chan workerACLRequest), life: life, fenceWorker: fenceWorker}
	var identity struct {
		ApplicationID string `json:"application_id"`
		BotUserID     string `json:"bot_user_id"`
	}
	backend, present := config.Backends["discord"]
	if !present {
		return a, nil
	}
	if err := json.Unmarshal(backend.Config, &identity); err != nil {
		return nil, err
	}
	for _, spec := range config.Modules {
		id := string(spec.ModuleID)
		var hasDiscord bool
		for _, approval := range spec.Approval.GetBackends() {
			if approval.GetBackendId() == "discord" && approval.GetProtocolMajor() == 2 && len(approval.GetCapabilities()) != 0 {
				hasDiscord = true
				break
			}
		}
		if !hasDiscord {
			continue
		}
		approved, err := (proto.MarshalOptions{Deterministic: true}).Marshal(spec.Approval)
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		for _, field := range [...]string{config.Host.BundleDigest, identity.ApplicationID, identity.BotUserID, id, spec.ImageDigest} {
			_, _ = h.Write([]byte(field))
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write(approved)
		binding := "sha256:" + hex.EncodeToString(h.Sum(nil))
		entry, hasACL := stored[id]
		status := discordacl.Status{Managed: spec.DiscordACLRequired || hasACL}
		if hasACL && entry.Binding == binding {
			status.Policy = entry.Policy
		}
		a.modules[id] = aclModule{binding: binding, status: status}
	}
	return a, nil
}

func (a *aclOwner) initialPolicies() map[string]discordacl.Policy {
	initial := make(map[string]discordacl.Policy)
	for id, module := range a.modules {
		if module.status.Managed {
			initial[id] = module.status.Policy
		}
	}
	return initial
}

func (a *aclOwner) control(ctx context.Context, op string, payload json.RawMessage) (json.RawMessage, error) {
	switch op {
	case discordacl.Show, discordacl.Guilds, discordacl.Channels, discordacl.Preview, discordacl.Apply:
	default:
		return nil, errors.New("unknown control operation")
	}
	var q discordacl.Query
	if err := gvxcontract.DecodeStrict(payload, 64<<10, 8, &q); err != nil || q.Module == "" || len(q.Module) > 64 {
		return nil, errors.New("invalid ACL request")
	}
	a.mu.Lock()
	module, ok := a.modules[q.Module]
	a.mu.Unlock()
	if !ok {
		return nil, errors.New("module not installed or has no approved Discord capabilities")
	}
	switch op {
	case discordacl.Show:
		if len(module.status.Labels) == 0 && len(module.status.Policy.Scopes) != 0 {
			module.status.Labels, _ = a.catalogLabels(ctx, module.status.Policy)
		}
		return json.Marshal(module.status)
	case discordacl.Guilds:
		guilds, err := discordsetup.ListGuilds(ctx, a.token)
		if err != nil {
			return nil, err
		}
		choices := make([]discordacl.Choice, 0, len(guilds))
		for _, guild := range guilds {
			choices = append(choices, discordacl.Choice{ID: guild.ID, Name: guild.Name})
		}
		return json.Marshal(choices)
	case discordacl.Channels:
		if !discordacl.ValidID(q.GuildID) {
			return nil, errors.New("invalid Discord server")
		}
		channels, err := discordsetup.ListChannels(ctx, a.token, q.GuildID)
		if err != nil {
			return nil, err
		}
		choices := make([]discordacl.Choice, 0, len(channels))
		for _, channel := range channels {
			choices = append(choices, discordacl.Choice{ID: channel.ID, Name: channel.Name})
		}
		return json.Marshal(choices)
	case discordacl.Preview:
		return a.preview(ctx, q, module)
	default:
		return a.apply(ctx, q)
	}
}

func normalizeACL(p discordacl.Policy) (discordacl.Policy, error) {
	if err := p.Validate(); err != nil {
		return discordacl.Policy{}, err
	}
	p.Scopes = append([]discordacl.Scope{}, p.Scopes...)
	slices.SortFunc(p.Scopes, func(a, b discordacl.Scope) int {
		if cmp := strings.Compare(a.GuildID, b.GuildID); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.ChannelID, b.ChannelID)
	})
	p.Scopes = slices.Compact(p.Scopes)
	return p, nil
}

func (a *aclOwner) preview(ctx context.Context, q discordacl.Query, observed aclModule) (json.RawMessage, error) {
	policy, err := normalizeACL(q.Policy)
	if err != nil {
		return nil, err
	}
	isSubset := observed.status.Managed
	for _, scope := range policy.Scopes {
		if !slices.ContainsFunc(observed.status.Policy.Scopes, func(old discordacl.Scope) bool {
			return old.GuildID == scope.GuildID && (old.ChannelID == "" || old.ChannelID == scope.ChannelID)
		}) {
			isSubset = false
			break
		}
	}
	var labels []string
	if len(policy.Scopes) != 0 {
		catalog, cancel := context.WithTimeout(ctx, 20*time.Second)
		labels, err = a.catalogLabels(catalog, policy)
		cancel()
		if err != nil && !isSubset {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	value := rand.Text()
	a.mu.Lock()
	defer a.mu.Unlock()
	current := a.modules[q.Module]
	if current.status.Managed != observed.status.Managed || !slices.Equal(current.status.Policy.Scopes, observed.status.Policy.Scopes) {
		return nil, errors.New("ACL changed in another shell; run chatanium acl set again")
	}
	next := discordacl.Status{Managed: true, Policy: policy, Labels: labels}
	current.review = aclReview{status: next, token: value}
	a.modules[q.Module] = current
	return json.Marshal(discordacl.Plan{Before: current.status, After: next, Digest: value})
}

func (a *aclOwner) apply(ctx context.Context, q discordacl.Query) (json.RawMessage, error) {
	policy, err := normalizeACL(q.Policy)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	m := a.modules[q.Module]
	if q.Approval == "" || q.Approval != m.review.token || !slices.Equal(policy.Scopes, m.review.status.Policy.Scopes) {
		return nil, errors.New("ACL approval is missing or stale; run chatanium acl set again")
	}
	next := m.review.status
	m.review = aclReview{}
	a.modules[q.Module] = m
	if m.status.Managed && slices.Equal(policy.Scopes, m.status.Policy.Scopes) {
		return json.Marshal(m.status)
	}
	if err := a.db.SetDiscordACL(ctx, a.epoch, a.revision, q.Module, store.DiscordACLRecord{Binding: m.binding, Policy: policy}); err != nil {
		return nil, err
	}
	a.sequence++
	req := workerACLRequest{change: session.WorkerACLChange{ModuleID: q.Module, Revision: a.sequence, Policy: policy}, result: make(chan error, 1)}
	apply, cancel := context.WithTimeout(a.life, 20*time.Second)
	defer cancel()
	select {
	case a.worker <- req:
		select {
		case err = <-req.result:
		case <-apply.Done():
			err = apply.Err()
		}
	case <-apply.Done():
		err = apply.Err()
	}
	if err != nil {
		a.fenceWorker()
		return nil, errors.New("ACL saved but live delivery could not be confirmed; the runtime is stopping to prevent stale access")
	}
	m.status = next
	a.modules[q.Module] = m
	return json.Marshal(m.status)
}

func (a *aclOwner) catalogLabels(ctx context.Context, policy discordacl.Policy) ([]string, error) {
	if len(policy.Scopes) == 0 {
		return nil, nil
	}
	guilds, err := discordsetup.ListGuilds(ctx, a.token)
	if err != nil {
		return nil, err
	}
	guildNames := make(map[string]string, len(guilds))
	for _, guild := range guilds {
		guildNames[guild.ID] = guild.Name
	}
	channels := make(map[string]map[string]string)
	labels := make([]string, 0, len(policy.Scopes))
	for _, scope := range policy.Scopes {
		label, found := guildNames[scope.GuildID]
		if !found {
			return nil, errors.New("Discord bot cannot access a selected server")
		}
		if scope.ChannelID != "" {
			known := channels[scope.GuildID]
			if known == nil {
				list, err := discordsetup.ListChannels(ctx, a.token, scope.GuildID)
				if err != nil {
					return nil, err
				}
				known = make(map[string]string, len(list))
				for _, channel := range list {
					known[channel.ID] = channel.Name
				}
				channels[scope.GuildID] = known
			}
			channel, found := known[scope.ChannelID]
			if !found {
				return nil, errors.New("selected Discord channel is not available in its server")
			}
			label = fmt.Sprintf("%s / #%s", label, channel)
		}
		labels = append(labels, label)
	}
	return labels, nil
}
