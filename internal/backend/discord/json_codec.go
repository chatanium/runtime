package discordbackend

import (
	"encoding/json"
	"strconv"
	"time"

	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// jsonEncoder is a closed, generated type switch over reviewed DTOs. Maps below
// contain Discord JSON values only, never protobuf wrappers or credential refs.
// Presence is decided before encoding/json sees a field, so false, zero, empty
// collections and explicit null are not collapsed by SDK omitempty tags.
type jsonEncoder struct {
	active map[any]bool
	err    error
	depth  int
}

func (e *jsonEncoder) fail(_ string) {
	if e.err == nil {
		e.err = invalidRequest("")
	}
}
func (e *jsonEncoder) enter(v any) bool {
	if e.depth >= 128 || e.active[v] {
		e.fail("cyclic or excessively nested DTO")
		return false
	}
	e.active[v] = true
	e.depth++
	return true
}
func (e *jsonEncoder) leave(v any) { delete(e.active, v); e.depth-- }
func discordJSON(v any) (any, error) {
	e := &jsonEncoder{active: make(map[any]bool)}
	result := e.value(v)
	return result, e.err
}
func (e *jsonEncoder) special(src any) any {
	switch v := src.(type) {
	case *timestamppb.Timestamp:
		if v == nil || v.CheckValid() != nil {
			e.fail("invalid timestamp")
			return nil
		}
		return v.AsTime().Format(time.RFC3339Nano)
	case *corewire.NullableString:
		if v == nil {
			return nil
		}
		switch x := v.Kind.(type) {
		case *corewire.NullableString_Value:
			return x.Value
		case *corewire.NullableString_NullValue:
			return nil
		default:
			e.fail("nullable selection is required")
			return nil
		}
	case *corewire.NullableTimestamp:
		if v == nil {
			return nil
		}
		switch x := v.Kind.(type) {
		case *corewire.NullableTimestamp_Value:
			return e.special(x.Value)
		case *corewire.NullableTimestamp_NullValue:
			return nil
		default:
			e.fail("nullable selection is required")
			return nil
		}
	case *corewire.JSONValue:
		if v == nil || !json.Valid(v.Json) {
			e.fail("invalid JSON value")
			return nil
		}
		return json.RawMessage(v.Json)
	default:
		e.fail("unreviewed JSON type")
		return nil
	}
}

// applyAttachments reconciles the complete post-edit attachment set, preserving
// caller order and making each multipart files[n] correspond to precisely one
// JSON attachment id n. It does not fetch or implicitly retain old attachments.
func applyAttachments(body map[string]any, files []*wire.FileAttachment, edits *wire.AttachmentEditList, editing bool) error {
	if len(files) > 10 {
		return invalidRequest("too many attachments")
	}
	metadata := make([]map[string]any, len(files))
	for i, f := range files {
		if f == nil || f.UploadedFileRef == nil || f.Filename == "" {
			return invalidRequest("invalid file")
		}
		metadata[i] = map[string]any{"id": i, "filename": f.Filename}
		if f.Description != nil {
			metadata[i]["description"] = *f.Description
		}
	}
	if !editing {
		if edits != nil {
			return invalidRequest("attachment edit not supported")
		}
		if len(files) > 0 {
			body["attachments"] = metadata
		}
		return nil
	}
	if edits == nil {
		if len(files) > 0 {
			return invalidRequest("complete attachment set is required")
		}
		return nil
	}
	if len(edits.Values) > 10 {
		return invalidRequest("too many attachments")
	}
	seenIDs := make(map[string]bool)
	seenFiles := make([]bool, len(files))
	result := make([]any, len(edits.Values))
	for i, entry := range edits.Values {
		if entry == nil {
			return invalidRequest("null attachment entry")
		}
		switch source := entry.Source.(type) {
		case *wire.AttachmentEditEntry_ExistingAttachmentId:
			id := source.ExistingAttachmentId
			if id == "" || seenIDs[id] {
				return invalidRequest("invalid retained attachment")
			}
			seenIDs[id] = true
			value := map[string]any{"id": id}
			if entry.Filename != nil {
				if *entry.Filename == "" {
					return invalidRequest("empty filename")
				}
				value["filename"] = *entry.Filename
			}
			if entry.Description != nil {
				value["description"] = *entry.Description
			}
			result[i] = value
		case *wire.AttachmentEditEntry_NewFileIndex:
			index := uint64(source.NewFileIndex)
			if index >= uint64(len(files)) || seenFiles[index] {
				return invalidRequest("invalid file index")
			}
			seenFiles[index] = true
			file := files[index]
			if entry.Filename != nil && *entry.Filename != file.Filename {
				return invalidRequest("conflicting attachment metadata")
			}
			if entry.Description != nil && (file.Description == nil || *entry.Description != *file.Description) {
				return invalidRequest("conflicting attachment metadata")
			}
			result[i] = metadata[index]
		default:
			return invalidRequest("attachment source is required")
		}
	}
	for _, seen := range seenFiles {
		if !seen {
			return invalidRequest("every uploaded file must be selected")
		}
	}
	body["attachments"] = result
	return nil
}

func decimalPermission(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	_, err := strconv.ParseInt(s, 10, 64)
	return err == nil
}
