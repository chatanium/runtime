package discordbackend

import (
	"context"
	"strconv"
	"time"

	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Discord's initial-response window is a protocol rule, not an operator default:
// https://docs.discord.com/developers/interactions/receiving-and-responding#interaction-callback
func initialCallbackDeadline(id string) (time.Time, error) {
	value, e := strconv.ParseUint(id, 10, 64)
	if e != nil || value == 0 {
		return time.Time{}, denied("CREDENTIAL_REFERENCE_INVALID")
	}
	return time.UnixMilli(int64(value>>22) + 1420070400000).Add(3 * time.Second), nil
}
func (h *Helper) validateInitialCallback(ctx context.Context, operation string, request proto.Message, op *OperationContext, plan *RESTPlan) error {
	if operation != "InteractionRespond" {
		return nil
	}
	req, ok := request.(*wire.InteractionRespondRequest)
	if !ok || req.Interaction == nil || req.Resp == nil || len(plan.Credentials) != 1 {
		return invalid("DISCORD_INTERACTION_INVALID")
	}
	use := plan.Credentials[0]
	h.backend.mu.Lock()
	record := h.backend.vault[use.Ref.OpaqueId]
	if record == nil || record.owner != op.Principal || record.purpose != "discord.interaction" {
		h.backend.mu.Unlock()
		return denied("CREDENTIAL_REFERENCE_INVALID")
	}
	kind, message := record.interactionType, record.sourceMessageID
	// The stored source actor supplies authority even for identity-minimal
	// callback DTOs. Optional caller identities may only constrain, not grant.
	storedActor := record.resource.GetResourceIds()["user_id"]
	actor := req.Interaction.GetUser().GetId()
	memberActor := req.Interaction.GetMember().GetUser().GetId()
	if !snowflake(storedActor) || (actor != "" && actor != storedActor) || (memberActor != "" && memberActor != storedActor) {
		h.backend.mu.Unlock()
		return denied("CREDENTIAL_REFERENCE_INVALID")
	}
	h.backend.mu.Unlock()
	if int64(req.Interaction.GetType()) != int64(kind) {
		return denied("CREDENTIAL_INTERACTION_TYPE_MISMATCH")
	}
	response := int64(req.Resp.GetType())
	valid := false
	switch kind {
	case 1:
		valid = response == 1
	case 2:
		valid = response == 4 || response == 5 || response == 9
	case 3:
		valid = response == 4 || response == 5 || response == 9 || ((response == 6 || response == 7) && message != "")
	case 4:
		valid = response == 8
	case 5:
		valid = response == 4 || response == 5 || ((response == 6 || response == 7) && message != "")
	}
	if !valid {
		s := status.New(codes.InvalidArgument, "UNSUPPORTED_VARIANT")
		if detail, e := s.WithDetails(&corewire.ErrorDetail{Origin: corewire.ErrorOrigin_ERROR_ORIGIN_FLEXMODULE, Reason: "UNSUPPORTED_VARIANT", BackendId: BackendID, RemoteOutcome: corewire.RemoteOutcome_REMOTE_OUTCOME_NOT_SENT, Violations: []*corewire.FieldViolation{{FieldPath: "resp.type", Reason: "UNSUPPORTED_VARIANT", Description: "response kind is not valid for the delivered interaction"}}}); e == nil {
			s = detail
		}
		return s.Err()
	}
	return ctx.Err()
}
