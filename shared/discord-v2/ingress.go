package discordv2

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bwmarrin/discordgo"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ingressNode borrows exact spans only during projection. Returned scalar values
// and audit bytes own their storage; nested objects/arrays are parsed once.
type ingressNode struct {
	raw     []byte
	object  map[string]*ingressNode
	array   []*ingressNode
	null    bool
	omitted map[string]bool
}

func (n *ingressNode) get(k string) *ingressNode {
	if n == nil || n.omitted[k] {
		return nil
	}
	return n.object[k]
}

func (c *conversion) interactionIngressUser(n *ingressNode, guild, path string) (string, error) {
	memberUser, user := "", ""
	for index, node := range []*ingressNode{n.get("member").get("user").get("id"), n.get("user").get("id")} {
		if node == nil || node.null {
			continue
		}
		id, err := ingressScalar[string](node, c, path)
		if err != nil {
			return "", err
		}
		if index == 0 {
			memberUser = id
		} else {
			user = id
		}
	}
	return c.interactionUser(guild, memberUser, user, path)
}
func (n *ingressNode) without(keys ...string) *ingressNode {
	if len(keys) == 0 {
		return n
	}
	v := *n
	v.omitted = make(map[string]bool, len(n.omitted)+len(keys))
	for k, b := range n.omitted {
		v.omitted[k] = b
	}
	for _, k := range keys {
		v.omitted[k] = true
	}
	return &v
}
func (n *ingressNode) has(keys ...string) bool {
	for _, k := range keys {
		if n.get(k) != nil {
			return true
		}
	}
	return false
}
func parseIngress(raw []byte, c *conversion) (*ingressNode, error) {
	if err := exactIngressJSON(raw, c); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	node, err := readIngressNode(d, raw, c)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, c.fail("InvalidJSON", "", "expected one event object")
	}
	if node.object == nil {
		return nil, c.fail("InvalidJSON", "", "expected event object")
	}
	return node, nil
}
func exactIngressJSON(raw []byte, c *conversion) error {
	if len(raw) == 0 || !utf8.Valid(raw) {
		return c.fail("InvalidJSON", "", "expected valid UTF-8 gateway JSON")
	}
	return nil
}
func readIngressNode(d *json.Decoder, raw []byte, c *conversion) (*ingressNode, error) {
	start := int(d.InputOffset())
	for start < len(raw) && (raw[start] == ' ' || raw[start] == '\n' || raw[start] == '\r' || raw[start] == '\t' || raw[start] == ':' || raw[start] == ',') {
		start++
	}
	t, err := d.Token()
	if err != nil {
		return nil, c.fail("InvalidJSON", "", "invalid gateway JSON")
	}
	n := &ingressNode{null: t == nil}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			n.object = make(map[string]*ingressNode)
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, c.fail("InvalidJSON", "", "invalid gateway object")
				}
				k, ok := key.(string)
				if !ok {
					return nil, c.fail("InvalidJSON", "", "invalid gateway field")
				}
				if _, duplicate := n.object[k]; duplicate {
					return nil, c.fail("InvalidJSON", "", "duplicate gateway field")
				}
				v, err := readIngressNode(d, raw, c)
				if err != nil {
					return nil, err
				}
				n.object[k] = v
			}
			if _, err := d.Token(); err != nil {
				return nil, c.fail("InvalidJSON", "", "invalid gateway object")
			}
		case '[':
			n.array = make([]*ingressNode, 0)
			for d.More() {
				v, err := readIngressNode(d, raw, c)
				if err != nil {
					return nil, err
				}
				n.array = append(n.array, v)
			}
			if _, err := d.Token(); err != nil {
				return nil, c.fail("InvalidJSON", "", "invalid gateway array")
			}
		default:
			return nil, c.fail("InvalidJSON", "", "unexpected gateway delimiter")
		}
	}
	n.raw = raw[start:int(d.InputOffset())]
	return n, nil
}
func ingressScalar[T any](n *ingressNode, c *conversion, path string) (T, error) {
	var value T
	if n == nil || n.null || json.Unmarshal(n.raw, &value) != nil {
		return value, c.fail("InvalidValue", path, "JSON field does not match declared scalar")
	}
	return value, nil
}
func ingressNumericScalar[T any](n *ingressNode, c *conversion, path string) (T, error) {
	var value T
	if n == nil || n.null || len(n.raw) == 0 || (n.raw[0] != '-' && (n.raw[0] < '0' || n.raw[0] > '9')) {
		return value, c.fail("InvalidValue", path, "JSON value must be numeric")
	}
	if json.Unmarshal(n.raw, &value) != nil {
		return value, c.fail("OutOfRange", path, "numeric value exceeds declared scalar range")
	}
	return value, nil
}
func ingressString(n *ingressNode, c *conversion, path string) (string, error) {
	value, err := ingressScalar[string](n, c, path)
	if err != nil {
		return "", err
	}
	if credentialURL(value) {
		return "", c.fail("CredentialBoundaryRequired", path, "credential-bearing URL requires runtime policy")
	}
	return value, nil
}
func ingressFloat(n *ingressNode, c *conversion, path string) (float64, error) {
	f, err := ingressNumericScalar[float64](n, c, path)
	if err != nil {
		return 0, err
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, c.fail("OutOfRange", path, "numeric value must be finite")
	}
	return f, nil
}
func ingressTimestamp(n *ingressNode, c *conversion, path string) (*timestamppb.Timestamp, error) {
	s, err := ingressString(n, c, path)
	if err != nil {
		return nil, err
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil, c.fail("InvalidValue", path, "invalid timestamp")
	}
	return timestampToProto(t, c, path)
}
func ingressKind(n *ingressNode, key string, c *conversion, path string) (int64, error) {
	v := n.get(key)
	if v == nil || v.null {
		return 0, nil
	}
	return ingressNumericScalar[int64](v, c, fieldPath(path, key))
}
func ingressNumber(n *ingressNode, c *conversion, path string) (json.Number, error) {
	if n == nil || n.null || len(n.raw) == 0 || (n.raw[0] != '-' && (n.raw[0] < '0' || n.raw[0] > '9')) {
		return "", c.fail("InvalidValue", path, "JSON value must be numeric")
	}
	return ingressScalar[json.Number](n, c, path)
}
func ingressOptionValue(n *ingressNode, parent int64, c *conversion, path string) (*wire.ApplicationCommandOptionValue, error) {
	kind := discordgo.ApplicationCommandOptionType(parent)
	var v any
	switch kind {
	case discordgo.ApplicationCommandOptionInteger, discordgo.ApplicationCommandOptionNumber:
		num, err := ingressNumber(n, c, path)
		if err != nil {
			return nil, err
		}
		v = num
	case discordgo.ApplicationCommandOptionBoolean:
		b, err := ingressScalar[bool](n, c, path)
		if err != nil {
			return nil, err
		}
		v = b
	default:
		s, err := ingressString(n, c, path)
		if err != nil {
			return nil, err
		}
		v = s
	}
	return optionToWire(v, kind, c, path)
}
func ingressChoiceValue(n *ingressNode, parent int64, c *conversion, path string) (*wire.ApplicationCommandChoiceValue, error) {
	kind := discordgo.ApplicationCommandOptionType(parent)
	switch kind {
	case discordgo.ApplicationCommandOptionString:
		s, err := ingressString(n, c, path)
		if err != nil {
			return nil, err
		}
		return choiceToWire(s, kind, c, path)
	case discordgo.ApplicationCommandOptionInteger, discordgo.ApplicationCommandOptionNumber:
		num, err := ingressNumber(n, c, path)
		if err != nil {
			return nil, err
		}
		return choiceToWire(num, kind, c, path)
	default:
		return nil, c.fail("UnsupportedVariant", path, "choice parent type is required")
	}
}
func ingressMapKey(s string, unsigned bool, c *conversion, path string) (uint64, int64, error) {
	if unsigned {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, 0, c.fail("OutOfRange", path, "map key exceeds declared numeric range")
		}
		return v, 0, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, 0, c.fail("OutOfRange", path, "map key exceeds declared numeric range")
	}
	return 0, v, nil
}
func ingressPermission(n *ingressNode, c *conversion, path string) error {
	if n == nil || n.null {
		return nil
	}
	s := strings.TrimSpace(string(n.raw))
	if len(s) > 0 && s[0] == '"' {
		var err error
		s, err = ingressString(n, c, path)
		if err != nil {
			return err
		}
	}
	if _, err := parsePermissions(s); err != nil {
		return c.fail("OutOfRange", path, "permissions must be nonnegative decimal in SDK range")
	}
	return nil
}

func ingressAttachmentEntry(n *ingressNode, c *conversion, path string) (*wire.AttachmentEditEntry, error) {
	if n == nil || n.object == nil {
		return nil, c.fail("InvalidPresence", path, "attachment edit requires a typed source object")
	}
	existing, index := n.get("existing_attachment_id"), n.get("new_file_index")
	if (existing == nil) == (index == nil) {
		return nil, c.fail("InvalidPresence", path, "exactly one attachment source is required")
	}
	view := &AttachmentEditEntry{}
	if existing != nil {
		s, err := ingressString(existing, c, fieldPath(path, "Source"))
		if err != nil {
			return nil, err
		}
		view.Source = ExistingAttachmentID(s)
	} else {
		i, err := ingressNumericScalar[uint32](index, c, fieldPath(path, "Source"))
		if err != nil {
			return nil, err
		}
		view.Source = NewFileIndex(i)
	}
	if v := n.get("filename"); v != nil {
		s, err := ingressString(v, c, fieldPath(path, "Filename"))
		if err != nil {
			return nil, err
		}
		view.Filename = &s
	}
	if v := n.get("description"); v != nil {
		s, err := ingressString(v, c, fieldPath(path, "Description"))
		if err != nil {
			return nil, err
		}
		view.Description = &s
	}
	return c.toAttachmentEditEntry(view, path)
}

func validateIngressModal(n *ingressNode, inLabel bool, c *conversion, path string) error {
	if n == nil || n.null {
		return nil
	}
	if n.array != nil {
		for i, child := range n.array {
			if err := validateIngressModal(child, false, c, indexPath(path, i)); err != nil {
				return err
			}
		}
		return nil
	}
	if n.object == nil {
		return c.fail("InvalidValue", path, "expected modal component object")
	}
	kind, err := ingressKind(n, "type", c, path)
	if err != nil {
		return err
	}
	if kind == 19 && !inLabel {
		return c.fail("InvalidValue", path, "modal FileUpload must be a direct child of Label")
	}
	if child := n.get("component"); child != nil {
		if err := validateIngressModal(child, kind == 18, c, fieldPath(path, "Component")); err != nil {
			return err
		}
	}
	if children := n.get("components"); children != nil {
		if err := validateIngressModal(children, false, c, fieldPath(path, "Components")); err != nil {
			return err
		}
	}
	if child := n.get("accessory"); child != nil {
		if err := validateIngressModal(child, false, c, fieldPath(path, "Accessory")); err != nil {
			return err
		}
	}
	return nil
}

func validateAuditIngressKey(n *ingressNode, c *conversion, path string) error {
	key := n.get("key")
	if key == nil || key.null {
		return nil
	}
	value, err := ingressString(key, c, fieldPath(path, "Key"))
	if err != nil {
		return err
	}
	if credentialFieldKey(value) && (n.get("old_value") != nil || n.get("new_value") != nil) {
		return c.fail("CredentialBoundaryRequired", fieldPath(path, "Key"), "credential audit field requires approved typed runtime policy")
	}
	return nil
}
