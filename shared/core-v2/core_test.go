package corev2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestExactJSON(t *testing.T) {
	limits := JSONLimits{MaxBytes: 1024, MaxDepth: 3}
	for _, raw := range []string{"null", "false", "0", `"text"`, `{"n":9007199254740993,"decimal":1.2300,"empty":[],"null":null}`} {
		if err := ValidateExactJSON([]byte(raw), limits); err != nil {
			t.Fatalf("valid JSON rejected: %v", err)
		}
	}
	for _, raw := range []string{"", "{} null", "NaN", "Infinity", "-Infinity", "{", "[1,]", string([]byte{'"', 0xff, '"'})} {
		if err := ValidateExactJSON([]byte(raw), limits); err == nil {
			t.Fatal("invalid JSON accepted")
		}
	}
	if err := ValidateExactJSON([]byte(`[[[[]]]]`), limits); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("depth limit: %v", err)
	}
	if err := ValidateExactJSON([]byte(`{}`), JSONLimits{}); err == nil {
		t.Fatal("unbounded limits accepted")
	}
	if err := ValidateExactJSON([]byte(`null`), JSONLimits{MaxBytes: 3, MaxDepth: 1}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("byte limit: %v", err)
	}
	value, err := NewJSONValue([]byte(`{"n":9007199254740993,"d":1.2300}`), limits)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeExactJSON(value, limits)
	if err != nil {
		t.Fatal(err)
	}
	object := decoded.(map[string]any)
	if object["n"] != json.Number("9007199254740993") || object["d"] != json.Number("1.2300") {
		t.Fatal("numeric lexemes changed")
	}
	for _, raw := range []string{"null", "[]", `"config"`, "1"} {
		if err := ValidateConfigJSON(&wire.JSONValue{Json: []byte(raw)}, limits); err == nil {
			t.Fatal("non-object configuration accepted")
		}
	}
	if err := ValidateConfigJSON(&wire.JSONValue{Json: []byte(" \n{}\t")}, limits); err != nil {
		t.Fatal(err)
	}
}

func TestNewJSONValueOwnsBytes(t *testing.T) {
	raw := []byte(`{"a":1}`)
	value, err := NewJSONValue(raw, JSONLimits{MaxBytes: 100, MaxDepth: 2})
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = '['
	if string(value.Json) != `{"a":1}` {
		t.Fatal("wire value aliases caller buffer")
	}
}

func TestWorkReferenceContext(t *testing.T) {
	incoming := metadata.NewIncomingContext(context.Background(), metadata.Pairs(WorkRefMetadata, "active-ref", "module-id", "forged"))
	incoming = metadata.NewOutgoingContext(incoming, metadata.Pairs("module-id", "forged", "authorization", "secret"))
	ctx, finish := deliveryContext(incoming)
	md, _ := metadata.FromOutgoingContext(HelperContext(ctx))
	if len(md) != 1 || md.Get(WorkRefMetadata)[0] != "active-ref" {
		t.Fatal("unexpected propagated metadata")
	}
	finish()
	md, _ = metadata.FromOutgoingContext(HelperContext(ctx))
	if len(md) != 0 {
		t.Fatal("completed delivery retained work reference")
	}
	ctx, cancel := context.WithCancel(incoming)
	ctx, finish = deliveryContext(ctx)
	defer finish()
	cancel()
	md, _ = metadata.FromOutgoingContext(HelperContext(ctx))
	if len(md) != 0 {
		t.Fatal("canceled delivery retained work reference")
	}
	md, _ = metadata.FromOutgoingContext(HelperContext(incoming))
	if len(md) != 0 {
		t.Fatal("unbound inbound metadata propagated")
	}
}

func TestDuplicateWorkReferenceRejected(t *testing.T) {
	incoming := metadata.NewIncomingContext(context.Background(), metadata.Pairs(WorkRefMetadata, "one", WorkRefMetadata, "two"))
	ctx, finish := deliveryContext(incoming)
	defer finish()
	md, _ := metadata.FromOutgoingContext(HelperContext(ctx))
	if len(md) != 0 {
		t.Fatal("ambiguous work reference forwarded")
	}
}

func TestSafeRPCError(t *testing.T) {
	const unsafe = "https://example.invalid/token/RAW_SECRET response-body"
	for _, source := range []error{errors.New(unsafe), status.Error(codes.PermissionDenied, unsafe)} {
		err := SafeRPCError(source)
		if strings.Contains(err.Error(), unsafe) || strings.Contains(err.Error(), "RAW_SECRET") {
			t.Fatal("unsafe source text escaped")
		}
		if status.Code(err) != codes.Internal {
			t.Fatal("untrusted status preserved")
		}
		details := status.Convert(err).Details()
		if len(details) != 1 {
			t.Fatal("missing structured detail")
		}
		detail := details[0].(*wire.ErrorDetail)
		if detail.RemoteOutcome != wire.RemoteOutcome_REMOTE_OUTCOME_UNKNOWN {
			t.Fatal("unknown outcome changed to not-sent")
		}
	}
	safe := NewError(codes.PermissionDenied, ReasonScopeDenied)
	if got := SafeRPCError(fmt.Errorf("%s: %w", unsafe, safe)); got != safe {
		t.Fatal("safe diagnostic was not preserved")
	}
	if status.Code(SafeRPCError(context.Canceled)) != codes.Canceled {
		t.Fatal("cancellation lost")
	}
	if status.Code(SafeRPCError(context.DeadlineExceeded)) != codes.DeadlineExceeded {
		t.Fatal("deadline lost")
	}
	if NewError(codes.OK, ReasonInternal) == nil {
		t.Fatal("invalid error code became nil success")
	}
}

func TestStagePresence(t *testing.T) {
	for _, req := range []*wire.StageRequest{nil, {}, {Stage: wire.Stage_STAGE_INIT}, {Stage: wire.Stage_STAGE_START, InitContext: &wire.InitContext{}}} {
		if err := validateStage(req); err == nil {
			t.Fatal("invalid stage presence accepted")
		}
	}
	for _, req := range []*wire.StageRequest{{Stage: wire.Stage_STAGE_INIT, InitContext: &wire.InitContext{}}, {Stage: wire.Stage_STAGE_START}, {Stage: wire.Stage_STAGE_DRAIN}, {Stage: wire.Stage_STAGE_STOP}} {
		if err := validateStage(req); err != nil {
			t.Fatal(err)
		}
	}
}
