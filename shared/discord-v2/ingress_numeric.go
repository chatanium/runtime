package discordv2

import (
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// exactJSONRational validates a numeric token without converting it to binary64.
// An exponent beyond the mantissa length plus the target's 64-bit precision
// cannot yield a nonzero int64 (even after seconds-to-nanoseconds scaling).
// Reject that case before big.Rat could allocate a gigantic power of ten from a
// tiny token. This is a representation bound, not an operator transport limit.
func exactJSONRational(text string) (*big.Rat, bool) {
	if !json.Valid([]byte(text)) {
		return nil, false
	}
	if index := strings.IndexAny(text, "eE"); index >= 0 {
		exponent, err := strconv.ParseInt(text[index+1:], 10, 64)
		bound := int64(len(text)) + 64
		if err != nil || exponent > bound || exponent < -bound {
			zero := true
			for _, r := range text[:index] {
				if r != '-' && r != '.' && r != '0' {
					zero = false
					break
				}
			}
			if zero {
				return new(big.Rat), true
			}
			return nil, false
		}
	}
	value, ok := new(big.Rat).SetString(text)
	return value, ok
}
func exactJSONInt64(text string) (int64, bool) {
	if !strings.ContainsAny(text, ".eE") {
		if !json.Valid([]byte(text)) {
			return 0, false
		}
		value, err := strconv.ParseInt(text, 10, 64)
		return value, err == nil
	}
	rational, ok := exactJSONRational(text)
	if !ok || !rational.IsInt() || !rational.Num().IsInt64() {
		return 0, false
	}
	return rational.Num().Int64(), true
}
func ingressExactInt64(n *ingressNode, c *conversion, path string) (int64, error) {
	number, err := ingressNumber(n, c, path)
	if err != nil {
		return 0, err
	}
	value, ok := exactJSONInt64(string(number))
	if !ok {
		return 0, c.fail("OutOfRange", path, "numeric timestamp must be an exact signed 64-bit integer")
	}
	return value, nil
}

// Activity.UnmarshalJSON interprets created_at as Unix milliseconds, unlike
// ordinary SDK time.Time JSON fields, which use RFC3339 timestamps.
func ingressUnixMilliseconds(n *ingressNode, c *conversion, path string) (*timestamppb.Timestamp, error) {
	value, err := ingressNumericScalar[int64](n, c, path)
	if err != nil {
		return nil, err
	}
	return timestampToProto(time.UnixMilli(value), c, path)
}

// Activity.UnmarshalJSON uses json.Number for application_id and stores its
// exact numeric text as a string, accepting either a number or a numeric string.
func ingressNumberString(n *ingressNode, c *conversion, path string) (string, error) {
	value, err := ingressScalar[json.Number](n, c, path)
	if err != nil {
		return "", err
	}
	return value.String(), nil
}

// TooManyRequests.UnmarshalJSON consumes retry_after in seconds. The wire and
// SDK duration fields use nanoseconds; preserve exact representable fractions,
// rather than silently truncating through the SDK's float64/millisecond path.
func ingressSecondsDuration(n *ingressNode, c *conversion, path string) (int64, error) {
	number, err := ingressNumber(n, c, path)
	if err != nil {
		return 0, err
	}
	rational, ok := exactJSONRational(string(number))
	if !ok {
		return 0, c.fail("OutOfRange", path, "duration exceeds signed 64-bit nanoseconds")
	}
	rational.Mul(rational, big.NewRat(int64(time.Second), 1))
	if !rational.IsInt() || !rational.Num().IsInt64() {
		return 0, c.fail("OutOfRange", path, "duration requires exact signed 64-bit nanoseconds")
	}
	return rational.Num().Int64(), nil
}
