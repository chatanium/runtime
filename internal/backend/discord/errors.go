package discordbackend

import (
	"context"
	"errors"
	"github.com/thirdscam/chatanium/internal/backend/discord/discordhttp"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

func localError(code codes.Code, reason string) error {
	s := status.New(code, reason)
	if detailed, e := s.WithDetails(&corewire.ErrorDetail{Origin: corewire.ErrorOrigin_ERROR_ORIGIN_FLEXMODULE, Reason: reason, RemoteOutcome: corewire.RemoteOutcome_REMOTE_OUTCOME_NOT_SENT}); e == nil {
		s = detailed
	}
	return s.Err()
}

// External errors are never retained, formatted, wrapped or logged. A canceled
// write may already have mutated Discord, so its outcome is conservatively UNKNOWN.
func externalError(source error, reason string, dispatched bool) error {
	code := codes.Unavailable
	if errors.Is(source, context.Canceled) {
		code = codes.Canceled
	} else if errors.Is(source, context.DeadlineExceeded) {
		code = codes.DeadlineExceeded
	}
	outcome := corewire.RemoteOutcome_REMOTE_OUTCOME_NOT_SENT
	if dispatched {
		outcome = corewire.RemoteOutcome_REMOTE_OUTCOME_UNKNOWN
	}
	s := status.New(code, reason)
	if detailed, e := s.WithDetails(&corewire.ErrorDetail{Origin: corewire.ErrorOrigin_ERROR_ORIGIN_TRANSPORT, Reason: reason, RemoteOutcome: outcome}); e == nil {
		s = detailed
	}
	return s.Err()
}
func httpTransportError(source error, dispatched bool) error {
	if !dispatched {
		switch {
		case errors.Is(source, discordhttp.ErrInvalidRequest):
			return invalid("DISCORD_REQUEST_INVALID")
		case errors.Is(source, discordhttp.ErrBodyTooLarge), errors.Is(source, discordhttp.ErrHeadersTooLarge):
			return localError(codes.ResourceExhausted, "DISCORD_REQUEST_LIMIT")
		case errors.Is(source, discordhttp.ErrCapacity):
			return localError(codes.ResourceExhausted, "DISCORD_REQUEST_CAPACITY")
		}
	}
	return externalError(source, "DISCORD_HTTP_TRANSPORT_FAILED", dispatched)
}

// annotateError is the single typed RPC egress boundary. Only fixed diagnostics
// and reviewed typed details survive; source error strings are never copied.
func annotateError(err error, operation string) error {
	if err == nil {
		return nil
	}
	s, ok := status.FromError(err)
	if !ok {
		err = externalError(err, "DISCORD_BACKEND_FAILURE", false)
		s, _ = status.FromError(err)
	}
	p := s.Proto()
	found := false
	for n, encoded := range p.Details {
		detail := &corewire.ErrorDetail{}
		if encoded.MessageIs(detail) && encoded.UnmarshalTo(detail) == nil {
			detail.Operation = operation
			detail.BackendId = BackendID
			if detail.Reason == "INTERACTION_ROUTE_QUOTA_EXCEEDED" || detail.Reason == "DISCORD_NONCE_QUOTA_EXCEEDED" {
				detail.Reason = "QUOTA_EXCEEDED"
			}
			replacement, e := anypb.New(detail)
			if e == nil {
				p.Details[n] = replacement
				found = true
			}
		}
	}
	if !found {
		detail, _ := anypb.New(&corewire.ErrorDetail{Origin: corewire.ErrorOrigin_ERROR_ORIGIN_FLEXMODULE, Reason: s.Message(), Operation: operation, BackendId: BackendID, RemoteOutcome: corewire.RemoteOutcome_REMOTE_OUTCOME_NOT_SENT})
		p.Details = append(p.Details, detail)
	}
	return status.FromProto(p).Err()
}
func receivedError(err error) error {
	if err == nil {
		return nil
	}
	s, ok := status.FromError(err)
	if !ok {
		s, _ = status.FromError(unavailable("DISCORD_RESPONSE_INVALID"))
	}
	p := s.Proto()
	found := false
	for n, encoded := range p.Details {
		detail := &corewire.ErrorDetail{}
		if encoded.MessageIs(detail) && encoded.UnmarshalTo(detail) == nil {
			detail.RemoteOutcome = corewire.RemoteOutcome_REMOTE_OUTCOME_RESPONSE_RECEIVED
			replacement, e := anypb.New(detail)
			if e == nil {
				p.Details[n] = replacement
				found = true
			}
		}
	}
	if !found {
		detail, _ := anypb.New(&corewire.ErrorDetail{Origin: corewire.ErrorOrigin_ERROR_ORIGIN_BACKEND, Reason: s.Message(), BackendId: BackendID, RemoteOutcome: corewire.RemoteOutcome_REMOTE_OUTCOME_RESPONSE_RECEIVED})
		p.Details = append(p.Details, detail)
	}
	return status.FromProto(p).Err()
}
