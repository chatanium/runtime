package discordv2

import (
	"encoding/json"
	"math"
	"math/big"
	"strconv"

	"github.com/bwmarrin/discordgo"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
)

const maxInteractionInteger int64 = 9007199254740991
const maxInteractionNumber float64 = 9007199254740992

func integerValue(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) || math.Trunc(n) != n || n < -float64(maxInteractionInteger) || n > float64(maxInteractionInteger) {
			return 0, false
		}
		return int64(n), true
	case int:
		if int64(n) < -maxInteractionInteger || int64(n) > maxInteractionInteger {
			return 0, false
		}
		return int64(n), true
	case int64:
		if n < -maxInteractionInteger || n > maxInteractionInteger {
			return 0, false
		}
		return n, true
	case json.Number:
		i, ok := exactJSONInt64(string(n))
		if !ok {
			return 0, false
		}
		return i, i >= -maxInteractionInteger && i <= maxInteractionInteger
	default:
		return 0, false
	}
}
func numberValue(v any) (float64, bool) {
	var f float64
	switch n := v.(type) {
	case float64:
		f = n
	case json.Number:
		if !json.Valid([]byte(n)) {
			return 0, false
		}
		var err error
		f, err = strconv.ParseFloat(string(n), 64)
		if err != nil {
			return 0, false
		}
		if math.Abs(f) == maxInteractionNumber {
			// Outward rounding distinguishes an exact boundary from a decimal
			// just beyond it, without constructing an unbounded denominator.
			exactBound, _, err := big.ParseFloat(string(n), 10, 64, big.AwayFromZero)
			if err != nil {
				return 0, false
			}
			exactBound.Abs(exactBound)
			if exactBound.Cmp(big.NewFloat(maxInteractionNumber)) > 0 {
				return 0, false
			}
		}
	default:
		return 0, false
	}
	return f, !math.IsNaN(f) && !math.IsInf(f, 0) && f >= -maxInteractionNumber && f <= maxInteractionNumber
}
func optionToWire(value any, kind discordgo.ApplicationCommandOptionType, c *conversion, path string) (*wire.ApplicationCommandOptionValue, error) {
	out := &wire.ApplicationCommandOptionValue{}
	switch kind {
	case discordgo.ApplicationCommandOptionSubCommand, discordgo.ApplicationCommandOptionSubCommandGroup:
		if value != nil {
			return nil, c.fail("InvalidValue", path, "subcommands must not contain scalar values")
		}
		return nil, nil
	case discordgo.ApplicationCommandOptionInteger:
		i, ok := integerValue(value)
		if !ok {
			return nil, c.fail("OutOfRange", path, "INTEGER must be exact and inside Discord range")
		}
		out.Value = &wire.ApplicationCommandOptionValue_IntegerValue{IntegerValue: i}
	case discordgo.ApplicationCommandOptionNumber:
		f, ok := numberValue(value)
		if !ok {
			return nil, c.fail("OutOfRange", path, "NUMBER must be finite and inside Discord range")
		}
		out.Value = &wire.ApplicationCommandOptionValue_NumberValue{NumberValue: f}
	case discordgo.ApplicationCommandOptionBoolean:
		b, ok := value.(bool)
		if !ok {
			return nil, c.fail("InvalidValue", path, "BOOLEAN requires boolean value")
		}
		out.Value = &wire.ApplicationCommandOptionValue_BooleanValue{BooleanValue: b}
	case discordgo.ApplicationCommandOptionString, discordgo.ApplicationCommandOptionUser, discordgo.ApplicationCommandOptionChannel, discordgo.ApplicationCommandOptionRole, discordgo.ApplicationCommandOptionMentionable, discordgo.ApplicationCommandOptionAttachment:
		s, ok := value.(string)
		if !ok {
			return nil, c.fail("InvalidValue", path, "option requires string or ID value")
		}
		if credentialURL(s) {
			return nil, c.fail("CredentialBoundaryRequired", path, "credential-bearing URL requires runtime policy")
		}
		switch kind {
		case discordgo.ApplicationCommandOptionString:
			out.Value = &wire.ApplicationCommandOptionValue_StringValue{StringValue: s}
		case discordgo.ApplicationCommandOptionUser:
			out.Value = &wire.ApplicationCommandOptionValue_UserId{UserId: s}
		case discordgo.ApplicationCommandOptionChannel:
			out.Value = &wire.ApplicationCommandOptionValue_ChannelId{ChannelId: s}
		case discordgo.ApplicationCommandOptionRole:
			out.Value = &wire.ApplicationCommandOptionValue_RoleId{RoleId: s}
		case discordgo.ApplicationCommandOptionMentionable:
			out.Value = &wire.ApplicationCommandOptionValue_MentionableId{MentionableId: s}
		case discordgo.ApplicationCommandOptionAttachment:
			out.Value = &wire.ApplicationCommandOptionValue_AttachmentId{AttachmentId: s}
		}
	default:
		return nil, c.fail("UnsupportedVariant", path, "unsupported interaction option kind")
	}
	return out, nil
}
func optionFromWire(value *wire.ApplicationCommandOptionValue, kind discordgo.ApplicationCommandOptionType, c *conversion, path string) (any, error) {
	if kind == discordgo.ApplicationCommandOptionSubCommand || kind == discordgo.ApplicationCommandOptionSubCommandGroup {
		if value != nil {
			return nil, c.fail("InvalidValue", path, "subcommands must not contain scalar values")
		}
		return nil, nil
	}
	if value == nil {
		return nil, c.fail("InvalidPresence", path, "typed scalar option value is required")
	}
	var v any
	ok := false
	switch n := value.Value.(type) {
	case *wire.ApplicationCommandOptionValue_IntegerValue:
		if n != nil && kind == discordgo.ApplicationCommandOptionInteger {
			if n.IntegerValue < -maxInteractionInteger || n.IntegerValue > maxInteractionInteger {
				return nil, c.fail("OutOfRange", path, "INTEGER exceeds Discord range")
			}
			v = float64(n.IntegerValue)
			ok = true
		}
	case *wire.ApplicationCommandOptionValue_NumberValue:
		if n != nil && kind == discordgo.ApplicationCommandOptionNumber {
			f, valid := numberValue(n.NumberValue)
			if !valid {
				return nil, c.fail("OutOfRange", path, "NUMBER exceeds Discord range")
			}
			v = f
			ok = true
		}
	case *wire.ApplicationCommandOptionValue_BooleanValue:
		if n != nil && kind == discordgo.ApplicationCommandOptionBoolean {
			v = n.BooleanValue
			ok = true
		}
	case *wire.ApplicationCommandOptionValue_StringValue:
		if n != nil && kind == discordgo.ApplicationCommandOptionString {
			v = n.StringValue
			ok = true
		}
	case *wire.ApplicationCommandOptionValue_UserId:
		if n != nil && kind == discordgo.ApplicationCommandOptionUser {
			v = n.UserId
			ok = true
		}
	case *wire.ApplicationCommandOptionValue_ChannelId:
		if n != nil && kind == discordgo.ApplicationCommandOptionChannel {
			v = n.ChannelId
			ok = true
		}
	case *wire.ApplicationCommandOptionValue_RoleId:
		if n != nil && kind == discordgo.ApplicationCommandOptionRole {
			v = n.RoleId
			ok = true
		}
	case *wire.ApplicationCommandOptionValue_MentionableId:
		if n != nil && kind == discordgo.ApplicationCommandOptionMentionable {
			v = n.MentionableId
			ok = true
		}
	case *wire.ApplicationCommandOptionValue_AttachmentId:
		if n != nil && kind == discordgo.ApplicationCommandOptionAttachment {
			v = n.AttachmentId
			ok = true
		}
	}
	if !ok {
		return nil, c.fail("UnsupportedVariant", path, "option kind and value variant disagree")
	}
	if s, ok := v.(string); ok && credentialURL(s) {
		return nil, c.fail("CredentialBoundaryRequired", path, "credential-bearing URL requires runtime policy")
	}
	return v, nil
}
func choiceToWire(value any, kind discordgo.ApplicationCommandOptionType, c *conversion, path string) (*wire.ApplicationCommandChoiceValue, error) {
	switch kind {
	case discordgo.ApplicationCommandOptionString:
		s, ok := value.(string)
		if !ok {
			return nil, c.fail("InvalidValue", path, "STRING choice requires string")
		}
		if credentialURL(s) {
			return nil, c.fail("CredentialBoundaryRequired", path, "credential-bearing URL requires runtime policy")
		}
		return &wire.ApplicationCommandChoiceValue{Value: &wire.ApplicationCommandChoiceValue_StringValue{StringValue: s}}, nil
	case discordgo.ApplicationCommandOptionInteger:
		i, ok := integerValue(value)
		if !ok {
			return nil, c.fail("OutOfRange", path, "INTEGER choice must be exact and inside Discord range")
		}
		return &wire.ApplicationCommandChoiceValue{Value: &wire.ApplicationCommandChoiceValue_IntegerValue{IntegerValue: i}}, nil
	case discordgo.ApplicationCommandOptionNumber:
		f, ok := numberValue(value)
		if !ok {
			return nil, c.fail("OutOfRange", path, "NUMBER choice must be finite and inside Discord range")
		}
		return &wire.ApplicationCommandChoiceValue{Value: &wire.ApplicationCommandChoiceValue_NumberValue{NumberValue: f}}, nil
	default:
		return nil, c.fail("UnsupportedVariant", path, "choice parent must be STRING INTEGER or NUMBER")
	}
}
func choiceFromWire(value *wire.ApplicationCommandChoiceValue, kind discordgo.ApplicationCommandOptionType, c *conversion, path string) (any, error) {
	if value == nil {
		return nil, c.fail("InvalidPresence", path, "typed choice value is required")
	}
	switch v := value.Value.(type) {
	case *wire.ApplicationCommandChoiceValue_StringValue:
		if v != nil && kind == discordgo.ApplicationCommandOptionString {
			if credentialURL(v.StringValue) {
				return nil, c.fail("CredentialBoundaryRequired", path, "credential-bearing URL requires runtime policy")
			}
			return v.StringValue, nil
		}
	case *wire.ApplicationCommandChoiceValue_IntegerValue:
		if v != nil && kind == discordgo.ApplicationCommandOptionInteger {
			if v.IntegerValue < -maxInteractionInteger || v.IntegerValue > maxInteractionInteger {
				return nil, c.fail("OutOfRange", path, "INTEGER choice exceeds Discord range")
			}
			return float64(v.IntegerValue), nil
		}
	case *wire.ApplicationCommandChoiceValue_NumberValue:
		if v != nil && kind == discordgo.ApplicationCommandOptionNumber {
			f, ok := numberValue(v.NumberValue)
			if !ok {
				return nil, c.fail("OutOfRange", path, "NUMBER choice exceeds Discord range")
			}
			return f, nil
		}
	}
	return nil, c.fail("UnsupportedVariant", path, "choice parent and variant disagree")
}
func inferChoiceType(list *wire.DomainApplicationCommandOptionChoiceList, c *conversion, path string) (discordgo.ApplicationCommandOptionType, error) {
	if list == nil || len(list.Values) == 0 {
		return 0, nil
	}
	var kind discordgo.ApplicationCommandOptionType
	for i, v := range list.Values {
		if v == nil || v.Value == nil {
			return 0, c.fail("InvalidPresence", indexPath(path, i), "typed choice is required")
		}
		var k discordgo.ApplicationCommandOptionType
		switch v.Value.Value.(type) {
		case *wire.ApplicationCommandChoiceValue_StringValue:
			k = discordgo.ApplicationCommandOptionString
		case *wire.ApplicationCommandChoiceValue_IntegerValue:
			k = discordgo.ApplicationCommandOptionInteger
		case *wire.ApplicationCommandChoiceValue_NumberValue:
			k = discordgo.ApplicationCommandOptionNumber
		default:
			return 0, c.fail("UnsupportedVariant", indexPath(path, i), "unsupported choice variant")
		}
		if kind != 0 && kind != k {
			return 0, c.fail("InvalidValue", path, "mixed autocomplete choice kinds")
		}
		kind = k
	}
	return kind, nil
}
