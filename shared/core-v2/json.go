package corev2

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/grpc/codes"
)

// JSONLimits bounds input bytes and nested array/object containers. Both values
// must be positive; operators must choose finite values rather than defaults.
type JSONLimits struct {
	MaxBytes int
	MaxDepth int
}

// ValidateExactJSON accepts exactly one complete UTF-8 JSON value. It validates
// without converting numeric tokens to float64, preserving large integers and
// exact decimal/exponent lexemes. NaN, infinity and trailing values are invalid.
func ValidateExactJSON(raw []byte, limits JSONLimits) error {
	if limits.MaxBytes <= 0 || limits.MaxDepth <= 0 {
		return NewError(codes.InvalidArgument, ReasonInvalidLimits)
	}
	if len(raw) > limits.MaxBytes {
		return NewError(codes.ResourceExhausted, ReasonJSONLimit)
	}
	if !utf8.Valid(raw) {
		return NewError(codes.InvalidArgument, ReasonInvalidJSON)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := scanJSON(d, 0, limits.MaxDepth); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return NewError(codes.InvalidArgument, ReasonInvalidJSON)
	}
	return nil
}

func scanJSON(d *json.Decoder, depth, maxDepth int) error {
	t, err := d.Token()
	if err != nil {
		return NewError(codes.InvalidArgument, ReasonInvalidJSON)
	}
	delim, container := t.(json.Delim)
	if !container {
		return nil
	}
	if delim != '[' && delim != '{' {
		return NewError(codes.InvalidArgument, ReasonInvalidJSON)
	}
	if depth >= maxDepth {
		return NewError(codes.ResourceExhausted, ReasonJSONLimit)
	}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			if err != nil {
				return NewError(codes.InvalidArgument, ReasonInvalidJSON)
			}
			if _, ok := key.(string); !ok {
				return NewError(codes.InvalidArgument, ReasonInvalidJSON)
			}
		}
		if err := scanJSON(d, depth+1, maxDepth); err != nil {
			return err
		}
	}
	end, err := d.Token()
	if err != nil || (delim == '[' && end != json.Delim(']')) || (delim == '{' && end != json.Delim('}')) {
		return NewError(codes.InvalidArgument, ReasonInvalidJSON)
	}
	return nil
}

// NewJSONValue validates and copies exact bytes; nil does not mean JSON null.
func NewJSONValue(raw []byte, limits JSONLimits) (*wire.JSONValue, error) {
	if err := ValidateExactJSON(raw, limits); err != nil {
		return nil, err
	}
	return &wire.JSONValue{Json: bytes.Clone(raw)}, nil
}

// DecodeExactJSON returns a local dynamic view with json.Number numeric leaves.
// The wire representation remains the exact original bytes, not a re-encoding.
func DecodeExactJSON(value *wire.JSONValue, limits JSONLimits) (any, error) {
	if value == nil {
		return nil, NewError(codes.InvalidArgument, ReasonInvalidJSON)
	}
	if err := ValidateExactJSON(value.Json, limits); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(value.Json))
	d.UseNumber()
	var decoded any
	if err := d.Decode(&decoded); err != nil {
		return nil, NewError(codes.InvalidArgument, ReasonInvalidJSON)
	}
	return decoded, nil
}

// ValidateConfigJSON enforces the additional core configuration object contract.
// Whitespace is preserved; an absent value, array, scalar or null is not config.
func ValidateConfigJSON(value *wire.JSONValue, limits JSONLimits) error {
	if value == nil {
		return NewError(codes.InvalidArgument, ReasonInvalidJSON)
	}
	if err := ValidateExactJSON(value.Json, limits); err != nil {
		return err
	}
	trimmed := bytes.TrimSpace(value.Json)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return NewError(codes.InvalidArgument, ReasonInvalidJSON)
	}
	return nil
}
