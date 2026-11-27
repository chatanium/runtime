package discordbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	discordhttp "github.com/thirdscam/chatanium/internal/backend/discord/http"
	"github.com/thirdscam/chatanium/internal/discordacl"
	"github.com/thirdscam/chatanium/internal/runtime/upload"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (h *Helper) execute(ctx context.Context, operation string, request proto.Message) (proto.Message, error) {
	plan, err := buildRESTPlan(operation, request)
	if err != nil {
		return nil, err
	}
	op, err := h.authorize(ctx, operation, plan)
	if err != nil {
		return nil, err
	}
	defer op.Admission.Release()
	bounded, cancel := context.WithTimeout(op.Context, h.backend.config.HTTP.RequestDeadline)
	defer cancel()
	life, done, err := h.backend.beginWork(op.Principal)
	if err != nil {
		return nil, err
	}
	defer done()
	stop := context.AfterFunc(life, cancel)
	defer stop()
	// Route admission is held through the actual HTTP workers, including wait=false.
	for n := range plan.Routes {
		if plan.Routes[n].ApplicationID == "" {
			plan.Routes[n].ApplicationID = h.backend.config.ApplicationID
		}
	}
	releaseRoutes, err := h.backend.ownership.leaseRoutes(bounded, op.Principal.ModuleID, plan.Routes)
	if err != nil {
		return nil, err
	}
	defer releaseRoutes()
	dispatched, responded := false, false
	credentials := make([]*resolvedCredential, 0, len(plan.Credentials))
	defer func() {
		for _, c := range credentials {
			c.release(dispatched, responded)
		}
	}()
	if err = h.validateInitialCallback(bounded, operation, request, op, plan); err != nil {
		return nil, err
	}
	for _, use := range plan.Credentials {
		secret, lease, e := h.acquireCredential(bounded, op, use)
		if e != nil {
			return nil, e
		}
		credentials = append(credentials, lease)
		if e = use.Apply(secret); e != nil {
			return nil, e
		}
		stopLease := context.AfterFunc(lease.lease.Context(), cancel)
		defer stopLease()
		// Inherit the source lease directly so revocation is visible to projection
		// and Issue synchronously, not only when an AfterFunc is scheduled.
		deadline, _ := bounded.Deadline()
		leaseBounded, cancelLease := context.WithDeadline(lease.lease.Context(), deadline)
		stopOperation := context.AfterFunc(bounded, cancelLease)
		defer stopOperation()
		defer cancelLease()
		bounded = context.WithValue(leaseBounded, relationshipCacheKey{}, op.Context.Value(relationshipCacheKey{}))
	}
	if err = h.validateOwnedAttachments(bounded, plan, op); err != nil {
		return nil, err
	}
	if plan.NoDispatch {
		return &emptypb.Empty{}, nil
	}
	var claim *commandClaim
	if plan.Command != nil {
		claim, err = h.backend.beginCommand(bounded, op.Principal, plan.Command)
		if err != nil {
			return nil, err
		}
	}
	claimFinished := false
	defer func() {
		if claim != nil && !claimFinished {
			cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), h.backend.config.HTTP.RequestDeadline)
			defer done()
			if e := claim.finish(cleanup, dispatched, false, nil); e != nil {
				h.backend.config.OnError(e)
			}
		}
	}()
	leases := make([]*upload.UploadReadLease, 0, len(plan.Files))
	defer func() {
		for _, l := range leases {
			if e := l.Release(); e != nil {
				h.backend.config.OnError(e)
			}
		}
	}()
	if len(plan.Files) > h.backend.config.MaxFilesPerRequest {
		return nil, invalid("DISCORD_ATTACHMENT_LIMIT")
	}
	fileLimit := h.backend.config.FileMaxBytes
	if fileLimit > 20*1024*1024 {
		fileLimit = 20 * 1024 * 1024
	}
	// An observed interaction limit can narrow or raise the normal destination
	// limit, but never the operator bound or authenticated stored file size.
	for _, use := range plan.Credentials {
		if use.Purpose == "discord.interaction" {
			if limit := h.backend.interactionFileLimit(use.Ref); limit > 0 {
				fileLimit = limit
				if fileLimit > h.backend.config.FileMaxBytes {
					fileLimit = h.backend.config.FileMaxBytes
				}
			}
		}
	}
	for n, f := range plan.Files {
		if f == nil || f.UploadedFileRef == nil {
			return nil, invalid("DISCORD_ATTACHMENT_INVALID")
		}
		lease, e := h.backend.config.Uploads.AcquireReadLease(bounded, op.Principal, f.UploadedFileRef)
		if e != nil {
			return nil, e
		}
		leases = append(leases, lease)
		ref := lease.Reference()
		if ref.SizeBytes > uint64(fileLimit) {
			return nil, invalid("DISCORD_ATTACHMENT_LIMIT")
		}
		stopLease := context.AfterFunc(lease.Context(), cancel)
		defer stopLease()
		plan.Request.Files = append(plan.Request.Files, discordhttp.File{Name: fmt.Sprintf("files[%d]", n), Filename: f.Filename, ContentType: ref.ContentType, Size: int64(ref.SizeBytes), Open: lease.Open})
	}
	plan.Request.Owner = string(op.Principal.InstanceID)
	if plan.Request.Authorization == "" {
		plan.Request.Authorization = "Bot " + strings.TrimPrefix(h.backend.config.BotToken, "Bot ")
	}
	if plan.Request.MaxBodyBytes <= 0 || plan.Request.MaxBodyBytes > h.backend.config.RequestMaxBytes {
		plan.Request.MaxBodyBytes = h.backend.config.RequestMaxBytes
	}
	if (operation == "ChannelMessageSendComplex" || operation == "ForumThreadStartComplex") && plan.Request.MaxBodyBytes > 25*1024*1024 {
		plan.Request.MaxBodyBytes = 25 * 1024 * 1024
	}
	response, err := h.backend.transport.Do(bounded, plan.Request)
	dispatched = response.Dispatched
	if err != nil {
		return nil, httpTransportError(err, dispatched)
	}
	success := response.StatusCode >= 200 && response.StatusCode < 300
	responded = success
	if claim != nil {
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), h.backend.config.HTTP.RequestDeadline)
		e := claim.finish(cleanup, dispatched && response.StatusCode >= 500, success, response.Body)
		done()
		claimFinished = true
		if e != nil {
			return nil, receivedError(unavailable("DISCORD_OWNERSHIP_WRITE_FAILED"))
		}
	}
	if !success {
		return nil, discordHTTPError(response.StatusCode, response.Body)
	}
	if plan.RequireResponse && len(response.Body) == 0 {
		return nil, receivedError(unavailable("DISCORD_RESPONSE_INVALID"))
	}
	if plan.ValidateResult != nil {
		if err = plan.ValidateResult(bounded, response.Body, op.Scopes); err != nil {
			return nil, receivedError(err)
		}
	}
	if err = h.validateResultScopes(operation, response.Body, op); err != nil {
		return nil, receivedError(err)
	}
	if err = bounded.Err(); err != nil {
		return nil, receivedError(err)
	}
	result, err := projectRESTResponse(withRESTProjectionContext(bounded, plan), operation, response.Body, instanceEncoder{backend: h.backend, services: h.services}, h.backend.projectionPolicy)
	if err == nil {
		err = bounded.Err()
	}
	if err != nil {
		return nil, receivedError(err)
	}
	return result, nil
}

// Results are checked before issuing credentials or constructing module DTOs.
// Trusted root identity and relationship fields, not arbitrary nested author IDs,
// govern whether a collection's returned resources are in the admitted grant.
func (h *Helper) validateResultScopes(operation string, raw []byte, op *OperationContext) error {
	if len(raw) == 0 {
		return nil
	}
	grant, e := op.Admission.CapabilityGrant()
	if e != nil {
		return e
	}
	if operation == "UserVoiceState" {
		var actual struct {
			ChannelID string `json:"channel_id"`
		}
		if json.Unmarshal(raw, &actual) != nil {
			return unavailable("DISCORD_RESPONSE_INVALID")
		}
		if actual.ChannelID != "" {
			matched := false
			for _, s := range op.Scopes {
				matched = matched || s.GetSelector().ResourceIds["channel_id"] == actual.ChannelID
			}
			if !matched {
				return denied("RESOURCE_RELATIONSHIP_CHANGED")
			}
		}
	}
	if resourceFreeOperation(operation) && operation != "UserGuilds" {
		return nil
	}
	parent := commonResources(op.Scopes)
	if op.invokingUser != "" {
		parent["user_id"] = op.invokingUser
	}
	graph := resourceGraphContext{grant: grant, invokingUser: op.invokingUser}
	if err := graph.check(raw, resultKind(operation), parent, 0, false); err != nil {
		return err
	}
	var checked []discordacl.Scope
	if h.services.Authorizer.ManagedDiscordACL() {
		evidence := scopeEvidence{backend: h.backend}
		for _, target := range op.Scopes {
			evidence.add(selectorEvidence(target))
		}
		if evidence.walk(raw, discordacl.Scope{GuildID: parent["guild_id"], ChannelID: parent["channel_id"]}, resultKind(operation), 0) {
			checked = evidence.scopes
		}
	}
	return op.Admission.CheckDiscordResult(checked)
}

// Credential records include the ingress-observed limit; absent data never
// implies the upload store's much larger per-file storage ceiling.
func (b *Backend) interactionFileLimit(ref *corewire.CredentialRef) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ref != nil {
		if r := b.vault[ref.OpaqueId]; r != nil && r.purpose == "discord.interaction" {
			return r.fileLimit
		}
	}
	return 0
}
