package discordv2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ConversionError contains stable diagnostics, never source values or raw errors.
type ConversionError struct{ Code, Direction, Message, Path, Reason string }

func (e *ConversionError) Error() string {
	return e.Direction + " " + e.Message + "." + e.Path + ": " + e.Code + ": " + e.Reason
}

type Nullable[T any] struct {
	Value T
	Null  bool
}
type JSONValue struct{ Raw json.RawMessage }

// CredentialTarget contains only identifiers from the actual source object.
// Policy runs inside a trusted runtime boundary, never in a module converter.
type CredentialTarget struct {
	Purpose       string
	ResourceScope *corewire.ResourceSelector
}
type ProjectionPolicy func(context.Context, CredentialTarget) (core.CredentialBinding, error)
type conversion struct {
	direction, message string
	active             map[any]bool
	projecting         bool
	ctx                context.Context
	encoder            core.CredentialEncoder
	policy             ProjectionPolicy
}

func newConversion(direction, message string) *conversion {
	return &conversion{direction: direction, message: message}
}
func (c *conversion) fail(code, path, reason string) error {
	return &ConversionError{Code: code, Direction: c.direction, Message: c.message, Path: path, Reason: reason}
}
func (c *conversion) enter(p any) bool {
	if c.active[p] {
		return false
	}
	if c.active == nil {
		c.active = make(map[any]bool)
	}
	c.active[p] = true
	return true
}
func (c *conversion) leave(p any) { delete(c.active, p) }
func fieldPath(base, field string) string {
	if base == "" {
		return field
	}
	return base + "." + field
}
func indexPath(base string, index int) string { return base + "[" + strconv.Itoa(index) + "]" }
func copyPointer[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
func cloneTimestamp(p *timestamppb.Timestamp) *timestamppb.Timestamp {
	if p == nil {
		return nil
	}
	return &timestamppb.Timestamp{Seconds: p.Seconds, Nanos: p.Nanos}
}
func cloneCredential(p *corewire.CredentialRef) *corewire.CredentialRef {
	if p == nil {
		return nil
	}
	out := &corewire.CredentialRef{OpaqueId: p.OpaqueId, BackendId: p.BackendId, Purpose: p.Purpose, ExpiresAt: cloneTimestamp(p.ExpiresAt)}
	if p.ResourceScope != nil {
		out.ResourceScope = &corewire.ResourceSelector{}
		if p.ResourceScope.ResourceIds != nil {
			out.ResourceScope.ResourceIds = make(map[string]string, len(p.ResourceScope.ResourceIds))
			for k, v := range p.ResourceScope.ResourceIds {
				out.ResourceScope.ResourceIds[k] = v
			}
		}
	}
	return out
}
func cloneUploadedFile(p *corewire.UploadedFileRef) *corewire.UploadedFileRef {
	if p == nil {
		return nil
	}
	return &corewire.UploadedFileRef{OpaqueId: p.OpaqueId, FileName: p.FileName, ContentType: p.ContentType, SizeBytes: p.SizeBytes, ExpiresAt: cloneTimestamp(p.ExpiresAt)}
}
func validateCredentialRef(p *corewire.CredentialRef, c *conversion, path string) error {
	if p != nil && p.ExpiresAt != nil && p.ExpiresAt.CheckValid() != nil {
		return c.fail("InvalidValue", fieldPath(path, "ExpiresAt"), "invalid timestamp")
	}
	return nil
}
func timestampToProto(t time.Time, c *conversion, path string) (*timestamppb.Timestamp, error) {
	v := timestamppb.New(t)
	if v.CheckValid() != nil {
		return nil, c.fail("InvalidValue", path, "invalid timestamp")
	}
	return v, nil
}
func timestampFromProto(t *timestamppb.Timestamp, c *conversion, path string) (time.Time, error) {
	if t == nil {
		return time.Time{}, nil
	}
	if t.CheckValid() != nil {
		return time.Time{}, c.fail("InvalidValue", path, "invalid timestamp")
	}
	return t.AsTime(), nil
}

var invalidPermissions = errors.New("invalid decimal permissions")

func parsePermissions(s string) (int64, error) {
	if s == "" {
		return 0, invalidPermissions
	}
	var value int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, invalidPermissions
		}
		digit := int64(r - '0')
		if value > (9223372036854775807-digit)/10 {
			return 0, invalidPermissions
		}
		value = value*10 + digit
	}
	return value, nil
}

// Public attachment CDN URLs deliberately remain domain values, including signed
// expiry/query parameters. Only actual credential-bearing URL forms are rejected.
func credentialURL(s string) bool {
	if !strings.Contains(s, "://") {
		return false
	}
	if _, query, ok := strings.Cut(s, "?"); ok {
		query, _, _ = strings.Cut(query, "#")
		if credentialURLParameters(query) {
			return true
		}
	}
	if _, fragment, ok := strings.Cut(s, "#"); ok && credentialURLParameters(fragment) {
		return true
	}
	u, err := url.Parse(s)
	if err != nil {
		_, authority, _ := strings.Cut(s, "://")
		authority, _, _ = strings.Cut(authority, "/")
		return strings.Contains(authority, "@") || strings.Contains(s, "/webhooks/")
	}
	if u.User != nil {
		return true
	}
	path := strings.Trim(u.Path, "/")
	for path != "" {
		part, rest, _ := strings.Cut(path, "/")
		path = rest
		if part == "webhooks" {
			_, token, found := strings.Cut(rest, "/")
			if found && token != "" {
				return true
			}
		}
	}
	return false
}
func credentialURLParameters(raw string) bool {
	for raw != "" {
		part, rest, _ := strings.Cut(raw, "&")
		raw = rest
		key, _, _ := strings.Cut(part, "=")
		decoded, err := url.QueryUnescape(key)
		if err == nil {
			key = decoded
		}
		if credentialFieldKey(key) || strings.EqualFold(key, "auth") {
			return true
		}
	}
	return false
}
func credentialFieldKey(key string) bool {
	switch strings.ToLower(key) {
	case "token", "access_token", "authorization", "bot_token", "webhook_token", "session_id", "resume_gateway_url":
		return true
	}
	return false
}
func credentialJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	return scanCredentialJSON(d)
}
func scanCredentialJSON(d *json.Decoder) bool {
	token, err := d.Token()
	if err != nil {
		return false
	}
	if value, ok := token.(string); ok {
		return credentialURL(value)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return false
	}
	for d.More() {
		if delimiter == '{' {
			key, err := d.Token()
			if err != nil {
				return false
			}
			if credentialFieldKey(key.(string)) || credentialURL(key.(string)) {
				return true
			}
		}
		if scanCredentialJSON(d) {
			return true
		}
	}
	_, _ = d.Token()
	return false
}
func exactJSON(raw []byte, c *conversion, path string) error {
	// Structural bounds are derived from the already supplied finite input. Host
	// ingress/transport allocation limits remain explicit runtime policy.
	if core.ValidateExactJSON(raw, core.JSONLimits{MaxBytes: len(raw) + 1, MaxDepth: len(raw) + 1}) != nil {
		return c.fail("InvalidJSON", path, "expected one exact UTF-8 JSON value")
	}
	if credentialJSON(raw) {
		return c.fail("CredentialBoundaryRequired", path, "credential-bearing JSON requires typed runtime policy")
	}
	return nil
}
func jsonToWire(v *JSONValue, c *conversion, path string) (*corewire.JSONValue, error) {
	if v == nil {
		return nil, nil
	}
	if err := exactJSON(v.Raw, c, path); err != nil {
		return nil, err
	}
	return &corewire.JSONValue{Json: bytes.Clone(v.Raw)}, nil
}
func jsonFromWire(v *corewire.JSONValue, c *conversion, path string) (*JSONValue, error) {
	if v == nil {
		return nil, nil
	}
	if err := exactJSON(v.Json, c, path); err != nil {
		return nil, err
	}
	return &JSONValue{Raw: bytes.Clone(v.Json)}, nil
}

// Interaction credentials retain the authenticated invoking user, not a caller
// supplied helper context. Guild delivery requires Member.User; DM delivery
// requires User. Conflicting representations must never select a broader scope.
func (c *conversion) interactionUser(guild, memberUser, user, path string) (string, error) {
	actor := user
	if guild != "" {
		actor = memberUser
	}
	id, err := strconv.ParseUint(actor, 10, 64)
	if err != nil || id == 0 || (memberUser != "" && user != "" && memberUser != user) {
		return "", c.fail("CredentialBoundaryRequired", path, "interaction requires an unambiguous invoking user")
	}
	return actor, nil
}

func (c *conversion) interactionStructUser(src *discordgo.Interaction, path string) (string, error) {
	memberUser, user := "", ""
	if src.Member != nil && src.Member.User != nil {
		memberUser = src.Member.User.ID
	}
	if src.User != nil {
		user = src.User.ID
	}
	return c.interactionUser(src.GuildID, memberUser, user, path)
}

func (c *conversion) encode(purpose, id, app, guild, channel, user, secret, path string) (*corewire.CredentialRef, error) {
	if c.policy == nil || c.encoder == nil || c.ctx == nil {
		return nil, c.fail("CredentialBoundaryRequired", path, "trusted credential policy is required")
	}
	purpose = "discord." + purpose
	key := "webhook_id"
	if purpose == "discord.interaction" {
		key = "interaction_id"
	}
	resources := map[string]string{key: id}
	if purpose == "discord.interaction" {
		if user == "" {
			return nil, c.fail("CredentialBoundaryRequired", path, "interaction requires an invoking user")
		}
		resources["user_id"] = user
	}
	if app != "" {
		resources["application_id"] = app
	}
	if guild != "" {
		resources["guild_id"] = guild
	}
	if channel != "" {
		resources["channel_id"] = channel
	}
	// Give policy its own copy, so it cannot mutate the authoritative target.
	target := CredentialTarget{Purpose: purpose, ResourceScope: &corewire.ResourceSelector{ResourceIds: make(map[string]string, len(resources))}}
	for k, v := range resources {
		target.ResourceScope.ResourceIds[k] = v
	}
	binding, err := c.policy(c.ctx, target)
	if err != nil {
		return nil, c.fail("CredentialBoundaryRequired", path, "credential policy rejected source")
	}
	if binding.BackendID != "discord" || binding.Purpose != purpose || binding.ResourceScope == nil || id == "" || binding.ExpiresAt.IsZero() || !binding.ExpiresAt.After(time.Now()) || timestamppb.New(binding.ExpiresAt).CheckValid() != nil {
		return nil, c.fail("CredentialBoundaryRequired", path, "credential policy binding does not match source")
	}
	if len(binding.ResourceScope.ResourceIds) != len(resources) {
		return nil, c.fail("CredentialBoundaryRequired", path, "credential resource binding does not match source")
	}
	for k, v := range resources {
		if binding.ResourceScope.ResourceIds[k] != v {
			return nil, c.fail("CredentialBoundaryRequired", path, "credential resource binding does not match source")
		}
	}
	ref, err := c.encoder.EncodeCredential(c.ctx, binding, secret)
	if err != nil || ref == nil {
		return nil, c.fail("CredentialBoundaryRequired", path, "credential encoding failed")
	}
	if err := validateCredentialRef(ref, c, path); err != nil {
		return nil, err
	}
	return cloneCredential(ref), nil
}
