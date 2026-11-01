package discordv2

import (
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"strconv"
)

type FileAttachment struct {
	Ref         *corewire.UploadedFileRef
	Filename    string
	Description *string
}
type AttachmentEditSource interface{ isAttachmentEditSource() }
type ExistingAttachmentID string

func (ExistingAttachmentID) isAttachmentEditSource() {}

type NewFileIndex uint32

func (NewFileIndex) isAttachmentEditSource() {}

type AttachmentEditEntry struct {
	Source                AttachmentEditSource
	Filename, Description *string
}

func FileAttachmentToProto(src *FileAttachment) (*wire.FileAttachment, error) {
	return newConversion("StructToProto", "FileAttachment").toFileAttachment(src, "")
}
func ProtoToFileAttachment(src *wire.FileAttachment) (*FileAttachment, error) {
	return newConversion("ProtoToStruct", "FileAttachment").fromFileAttachment(src, "")
}
func (c *conversion) toFileAttachment(src *FileAttachment, path string) (*wire.FileAttachment, error) {
	if src == nil {
		return nil, nil
	}
	if src.Ref == nil || src.Ref.OpaqueId == "" {
		return nil, c.fail("UploadedFileRefRequired", fieldPath(path, "Ref"), "completed upload reference is required")
	}
	if src.Filename == "" {
		return nil, c.fail("InvalidValue", fieldPath(path, "Filename"), "filename is required")
	}
	if src.Ref.ExpiresAt != nil && src.Ref.ExpiresAt.CheckValid() != nil {
		return nil, c.fail("InvalidValue", fieldPath(path, "Ref.ExpiresAt"), "invalid timestamp")
	}
	return &wire.FileAttachment{UploadedFileRef: cloneUploadedFile(src.Ref), Filename: src.Filename, Description: copyPointer(src.Description)}, nil
}
func (c *conversion) fromFileAttachment(src *wire.FileAttachment, path string) (*FileAttachment, error) {
	if src == nil {
		return nil, nil
	}
	if src.UploadedFileRef == nil || src.UploadedFileRef.OpaqueId == "" {
		return nil, c.fail("UploadedFileRefRequired", fieldPath(path, "Ref"), "completed upload reference is required")
	}
	if src.Filename == "" {
		return nil, c.fail("InvalidValue", fieldPath(path, "Filename"), "filename is required")
	}
	if src.UploadedFileRef.ExpiresAt != nil && src.UploadedFileRef.ExpiresAt.CheckValid() != nil {
		return nil, c.fail("InvalidValue", fieldPath(path, "Ref.ExpiresAt"), "invalid timestamp")
	}
	return &FileAttachment{Ref: cloneUploadedFile(src.UploadedFileRef), Filename: src.Filename, Description: copyPointer(src.Description)}, nil
}
func AttachmentEditEntryToProto(src *AttachmentEditEntry) (*wire.AttachmentEditEntry, error) {
	return newConversion("StructToProto", "AttachmentEditEntry").toAttachmentEditEntry(src, "")
}
func ProtoToAttachmentEditEntry(src *wire.AttachmentEditEntry) (*AttachmentEditEntry, error) {
	return newConversion("ProtoToStruct", "AttachmentEditEntry").fromAttachmentEditEntry(src, "")
}
func validSnowflake(s string) bool {
	if s == "" || s[0] == '0' {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}
func (c *conversion) toAttachmentEditEntry(src *AttachmentEditEntry, path string) (*wire.AttachmentEditEntry, error) {
	if src == nil {
		return nil, nil
	}
	if src.Filename != nil && *src.Filename == "" {
		return nil, c.fail("InvalidValue", fieldPath(path, "Filename"), "empty filename is invalid")
	}
	dst := &wire.AttachmentEditEntry{Filename: copyPointer(src.Filename), Description: copyPointer(src.Description)}
	switch v := src.Source.(type) {
	case ExistingAttachmentID:
		if !validSnowflake(string(v)) {
			return nil, c.fail("InvalidValue", fieldPath(path, "Source"), "existing attachment ID is invalid")
		}
		dst.Source = &wire.AttachmentEditEntry_ExistingAttachmentId{ExistingAttachmentId: string(v)}
	case NewFileIndex:
		dst.Source = &wire.AttachmentEditEntry_NewFileIndex{NewFileIndex: uint32(v)}
	default:
		return nil, c.fail("InvalidPresence", fieldPath(path, "Source"), "exactly one supported attachment value variant is required")
	}
	return dst, nil
}
func (c *conversion) fromAttachmentEditEntry(src *wire.AttachmentEditEntry, path string) (*AttachmentEditEntry, error) {
	if src == nil {
		return nil, nil
	}
	if src.Filename != nil && *src.Filename == "" {
		return nil, c.fail("InvalidValue", fieldPath(path, "Filename"), "empty filename is invalid")
	}
	dst := &AttachmentEditEntry{Filename: copyPointer(src.Filename), Description: copyPointer(src.Description)}
	switch v := src.Source.(type) {
	case *wire.AttachmentEditEntry_ExistingAttachmentId:
		if v == nil || !validSnowflake(v.ExistingAttachmentId) {
			return nil, c.fail("InvalidValue", fieldPath(path, "Source"), "existing attachment ID is invalid")
		}
		dst.Source = ExistingAttachmentID(v.ExistingAttachmentId)
	case *wire.AttachmentEditEntry_NewFileIndex:
		if v == nil {
			return nil, c.fail("InvalidPresence", fieldPath(path, "Source"), "nil attachment variant")
		}
		dst.Source = NewFileIndex(v.NewFileIndex)
	default:
		return nil, c.fail("InvalidPresence", fieldPath(path, "Source"), "exactly one attachment source is required")
	}
	return dst, nil
}
func validateAttachmentSetView(files []FileAttachment, entries *[]AttachmentEditEntry, c *conversion, path string) error {
	if entries == nil {
		if len(files) != 0 {
			return c.fail("InvalidPresence", fieldPath(path, "Attachments"), "new files require complete post-edit attachment set")
		}
		return nil
	}
	seen := make([]bool, len(files))
	ids := make(map[string]bool)
	for i, e := range *entries {
		p := indexPath(fieldPath(path, "Attachments"), i)
		if e.Filename != nil && *e.Filename == "" {
			return c.fail("InvalidValue", fieldPath(p, "Filename"), "empty filename is invalid")
		}
		switch v := e.Source.(type) {
		case ExistingAttachmentID:
			if !validSnowflake(string(v)) {
				return c.fail("InvalidValue", fieldPath(p, "Source"), "existing attachment ID is invalid")
			}
			if ids[string(v)] {
				return c.fail("InvalidPresence", p, "duplicate existing attachment ID")
			}
			ids[string(v)] = true
		case NewFileIndex:
			if uint64(v) >= uint64(len(files)) {
				return c.fail("InvalidPresence", p, "new file index is out of range")
			}
			if seen[v] {
				return c.fail("InvalidPresence", p, "new file index appears more than once")
			}
			seen[v] = true
			f := files[v]
			if e.Filename != nil && *e.Filename != f.Filename {
				return c.fail("InvalidPresence", p, "new attachment filename conflicts with file metadata")
			}
			if e.Description != nil && (f.Description == nil || *e.Description != *f.Description) {
				return c.fail("InvalidPresence", p, "new attachment description conflicts with file metadata")
			}
		default:
			return c.fail("InvalidPresence", fieldPath(p, "Source"), "exactly one supported attachment value variant is required")
		}
	}
	for _, found := range seen {
		if !found {
			return c.fail("InvalidPresence", fieldPath(path, "Attachments"), "new file index is missing from complete set")
		}
	}
	return nil
}
func validateAttachmentSetWire(files *wire.FileAttachmentList, entries *wire.AttachmentEditList, c *conversion, path string) error {
	count := 0
	if files != nil {
		count = len(files.Values)
	}
	if entries == nil {
		if count != 0 {
			return c.fail("InvalidPresence", fieldPath(path, "Attachments"), "new files require complete post-edit attachment set")
		}
		return nil
	}
	seen := make([]bool, count)
	ids := make(map[string]bool)
	for i, e := range entries.Values {
		p := indexPath(fieldPath(path, "Attachments"), i)
		if e == nil {
			return c.fail("InvalidPresence", p, "null attachment element")
		}
		if e.Filename != nil && *e.Filename == "" {
			return c.fail("InvalidValue", fieldPath(p, "Filename"), "empty filename is invalid")
		}
		switch v := e.Source.(type) {
		case *wire.AttachmentEditEntry_ExistingAttachmentId:
			if v == nil || !validSnowflake(v.ExistingAttachmentId) {
				return c.fail("InvalidValue", fieldPath(p, "Source"), "existing attachment ID is invalid")
			}
			if ids[v.ExistingAttachmentId] {
				return c.fail("InvalidPresence", p, "duplicate existing attachment ID")
			}
			ids[v.ExistingAttachmentId] = true
		case *wire.AttachmentEditEntry_NewFileIndex:
			if v == nil {
				return c.fail("InvalidPresence", fieldPath(p, "Source"), "nil attachment variant")
			}
			index := v.NewFileIndex
			if uint64(index) >= uint64(count) {
				return c.fail("InvalidPresence", p, "new file index is out of range")
			}
			if seen[index] {
				return c.fail("InvalidPresence", p, "new file index appears more than once")
			}
			seen[index] = true
			f := files.Values[index]
			if f == nil {
				return c.fail("InvalidPresence", indexPath(fieldPath(path, "Files"), int(index)), "null file element")
			}
			if e.Filename != nil && *e.Filename != f.Filename {
				return c.fail("InvalidPresence", p, "new attachment filename conflicts with file metadata")
			}
			if e.Description != nil && (f.Description == nil || *e.Description != *f.Description) {
				return c.fail("InvalidPresence", p, "new attachment description conflicts with file metadata")
			}
		default:
			return c.fail("InvalidPresence", fieldPath(p, "Source"), "exactly one attachment source is required")
		}
	}
	for _, found := range seen {
		if !found {
			return c.fail("InvalidPresence", fieldPath(path, "Attachments"), "new file index is missing from complete set")
		}
	}
	return nil
}
