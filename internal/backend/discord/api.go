package discordbackend

import (
	"encoding/json"
	"errors"
	"math"
	"time"

	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	discordv2 "github.com/thirdscam/chatanium/shared/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

// Diagnostics are fixed; neither caller values nor SDK/HTTP error strings cross
// this boundary. Conversion paths are accepted only from the static P2 mapper.
func invalidRequest(_ string) error {
	return core.NewError(codes.InvalidArgument, core.ReasonInvalidArgument)
}
func invalidResponse() error { return core.NewError(codes.Internal, core.ReasonInternal) }
func safeConversionError(err error) error {
	var conversion *discordv2.ConversionError
	if !errors.As(err, &conversion) {
		return invalidRequest("")
	}
	code, reason := codes.InvalidArgument, "INVALID_ARGUMENT"
	switch conversion.Code {
	case "OutOfRange":
		code, reason = codes.OutOfRange, "NUMERIC_OUT_OF_RANGE"
	case "UnsupportedVariant":
		reason = "UNSUPPORTED_VARIANT"
	}
	detail := &corewire.ErrorDetail{Origin: corewire.ErrorOrigin_ERROR_ORIGIN_FLEXMODULE, Reason: reason, RemoteOutcome: corewire.RemoteOutcome_REMOTE_OUTCOME_NOT_SENT}
	path := conversion.Path
	if len(path) <= 512 {
		safe := true
		for _, c := range path {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '[' || c == ']') {
				safe = false
				break
			}
		}
		if safe && path != "" {
			detail.Violations = []*corewire.FieldViolation{{FieldPath: path, Reason: reason}}
		}
	}
	s := status.New(code, reason)
	if with, e := s.WithDetails(detail); e == nil {
		s = with
	}
	return s.Err()
}
func safeProjectionError(_ error) error { return invalidResponse() }

// discordHTTPError exposes only the reviewed numeric Discord metadata. In
// particular the remote message and nested error text may echo secrets and are
// never copied, even when a response claims to be a valid Discord API error.
func discordHTTPError(httpStatus int, body []byte) error {
	detail := &wire.DiscordErrorDetail{HttpStatus: int32(httpStatus)}
	var remote struct {
		Code       *int64      `json:"code"`
		RetryAfter json.Number `json:"retry_after"`
	}
	if json.Unmarshal(body, &remote) == nil {
		detail.ApiCode = remote.Code
		if seconds, err := remote.RetryAfter.Float64(); err == nil && seconds >= 0 && !math.IsNaN(seconds) && !math.IsInf(seconds, 0) && seconds <= float64(math.MaxInt64/int64(time.Second)) {
			detail.RetryAfter = durationpb.New(time.Duration(seconds * float64(time.Second)))
		}
	}
	code := codes.Unknown
	switch httpStatus {
	case 400:
		code = codes.InvalidArgument
	case 401:
		code = codes.FailedPrecondition
	case 403:
		code = codes.PermissionDenied
	case 404:
		code = codes.NotFound
	case 409:
		code = codes.Aborted
	case 429:
		code = codes.ResourceExhausted
	default:
		if httpStatus >= 500 {
			code = codes.Unavailable
		}
	}
	backend, _ := anypb.New(detail)
	outcome := corewire.RemoteOutcome_REMOTE_OUTCOME_RESPONSE_RECEIVED
	s := status.New(code, "DISCORD_HTTP_ERROR")
	if with, err := s.WithDetails(&corewire.ErrorDetail{Origin: corewire.ErrorOrigin_ERROR_ORIGIN_BACKEND, Reason: "DISCORD_HTTP_ERROR", BackendId: BackendID, RemoteOutcome: outcome, BackendDetail: backend}); err == nil {
		s = with
	}
	return s.Err()
}

func credentialMismatch() error {
	s := status.New(codes.PermissionDenied, "REF_SCOPE_MISMATCH")
	if with, err := s.WithDetails(&corewire.ErrorDetail{Origin: corewire.ErrorOrigin_ERROR_ORIGIN_FLEXMODULE, Reason: "REF_SCOPE_MISMATCH", BackendId: BackendID, RemoteOutcome: corewire.RemoteOutcome_REMOTE_OUTCOME_NOT_SENT}); err == nil {
		s = with
	}
	return s.Err()
}

func numericRange(path string) error {
	return safeConversionError(&discordv2.ConversionError{Code: "OutOfRange", Path: path})
}
