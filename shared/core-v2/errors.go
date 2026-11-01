package corev2

import (
	"context"
	"errors"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Reason selects a fixed safe diagnostic. Arbitrary source error text, URLs,
// response bodies, secret values and caller-provided strings are never copied.
type Reason uint8

const (
	ReasonInternal Reason = iota
	ReasonInvalidArgument
	ReasonProtocolMismatch
	ReasonInvalidStage
	ReasonInvalidStatus
	ReasonInvalidJSON
	ReasonJSONLimit
	ReasonInvalidLimits
	ReasonHelperUnavailable
	ReasonHelperStartup
	ReasonHelperBinding
	ReasonAlreadyInitialized
	ReasonNotInitialized
	ReasonUploadSequence
	ReasonUploadSizeMismatch
	ReasonUploadTooLarge
	ReasonChunkTooLarge
	ReasonSourceRead
	ReasonCanceled
	ReasonDeadlineExceeded
	ReasonUnauthenticated
	ReasonCapabilityDenied
	ReasonScopeDenied
	ReasonInstanceNotRunning
	ReasonInstanceDraining
	ReasonQuotaExceeded
	ReasonRefNotFound
	ReasonRefExpired
	ReasonUnsupportedVariant
	ReasonNumericOutOfRange
)

var reasonNames = [...]string{
	"INTERNAL", "INVALID_ARGUMENT", "PROTOCOL_MISMATCH", "INVALID_STAGE",
	"INVALID_STATUS", "INVALID_JSON", "JSON_LIMIT_EXCEEDED", "INVALID_LIMITS",
	"HELPER_UNAVAILABLE", "HELPER_STARTUP_FAILED", "HELPER_BINDING_FAILED",
	"ALREADY_INITIALIZED", "NOT_INITIALIZED", "UPLOAD_SEQUENCE_INVALID",
	"UPLOAD_SIZE_MISMATCH", "UPLOAD_TOO_LARGE", "CHUNK_TOO_LARGE",
	"SOURCE_READ_FAILED", "CANCELLED", "DEADLINE_EXCEEDED",
	"UNAUTHENTICATED_INSTANCE", "REQUIRED_CAPABILITY_DENIED", "RESOURCE_SCOPE_DENIED",
	"INSTANCE_NOT_RUNNING", "INSTANCE_DRAINING", "QUOTA_EXCEEDED", "REF_NOT_FOUND",
	"REF_EXPIRED", "UNSUPPORTED_VARIANT", "NUMERIC_OUT_OF_RANGE",
}

// SafeError is a locally constructed structured status whose text is fixed.
// It deliberately does not retain an unsafe source error as an unwrap cause.
type SafeError struct{ value *status.Status }

func (e *SafeError) Error() string { return e.GRPCStatus().Err().Error() }

// GRPCStatus allows grpc-go to transmit the safe status and typed detail.
func (e *SafeError) GRPCStatus() *status.Status {
	if e == nil || e.value == nil {
		return status.New(codes.Internal, reasonNames[ReasonInternal])
	}
	return e.value
}

// NewError creates a fixed diagnostic without retaining arbitrary source text.
// Local rejections are NOT_SENT; helper transport failures conservatively report
// UNKNOWN. Invalid codes/reasons fail closed rather than returning nil success.
func NewError(code codes.Code, reason Reason) *SafeError {
	if reason == ReasonHelperUnavailable || reason == ReasonHelperStartup {
		return errorStatus(code, reason, wire.ErrorOrigin_ERROR_ORIGIN_TRANSPORT, wire.RemoteOutcome_REMOTE_OUTCOME_UNKNOWN)
	}
	return errorStatus(code, reason, wire.ErrorOrigin_ERROR_ORIGIN_FLEXMODULE, wire.RemoteOutcome_REMOTE_OUTCOME_NOT_SENT)
}

func errorStatus(code codes.Code, reason Reason, origin wire.ErrorOrigin, outcome wire.RemoteOutcome) *SafeError {
	if code == codes.OK || code > codes.Unauthenticated {
		code = codes.Internal
	}
	if int(reason) >= len(reasonNames) {
		reason = ReasonInternal
	}
	name := reasonNames[reason]
	s := status.New(code, name)
	withDetail, err := s.WithDetails(&wire.ErrorDetail{
		Origin:        origin,
		Reason:        name,
		RemoteOutcome: outcome,
	})
	if err == nil {
		s = withDetail
	}
	return &SafeError{value: s}
}

// SafeRPCError preserves only locally minted safe errors and cancellation.
// Unknown application errors (even arbitrary status errors) become INTERNAL;
// their messages, details and causes must not cross the module boundary.
func SafeRPCError(err error) error {
	if err == nil {
		return nil
	}
	var safe *SafeError
	if errors.As(err, &safe) && safe != nil && safe.value != nil {
		return safe
	}
	if errors.Is(err, context.Canceled) || (safe == nil && status.Code(err) == codes.Canceled) {
		return errorStatus(codes.Canceled, ReasonCanceled, wire.ErrorOrigin_ERROR_ORIGIN_FLEXMODULE, wire.RemoteOutcome_REMOTE_OUTCOME_UNKNOWN)
	}
	if errors.Is(err, context.DeadlineExceeded) || (safe == nil && status.Code(err) == codes.DeadlineExceeded) {
		return errorStatus(codes.DeadlineExceeded, ReasonDeadlineExceeded, wire.ErrorOrigin_ERROR_ORIGIN_FLEXMODULE, wire.RemoteOutcome_REMOTE_OUTCOME_UNKNOWN)
	}
	return errorStatus(codes.Internal, ReasonInternal, wire.ErrorOrigin_ERROR_ORIGIN_FLEXMODULE, wire.RemoteOutcome_REMOTE_OUTCOME_UNKNOWN)
}
