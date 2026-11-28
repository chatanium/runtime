package discordhttp

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// headerSize never constructs a second copy of arbitrary header values.
func headerSize(header http.Header, max int64) int64 {
	var size int64
	for key, values := range header {
		if len(values) == 0 {
			if int64(len(key)) > max-size || max-size-int64(len(key)) < 4 {
				return -1
			}
			size += int64(len(key)) + 4
		}
		for _, value := range values {
			if int64(len(key)) > max-size {
				return -1
			}
			size += int64(len(key))
			if max-size < 4 || int64(len(value)) > max-size-4 {
				return -1
			}
			size += int64(len(value)) + 4
		}
	}
	return size
}

func cleanText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (t *Transport) validate(r Request) error {
	if r.Owner == "" || r.Bucket == "" || r.MaxBodyBytes <= 0 {
		return ErrInvalidRequest
	}
	if int64(len(r.JSON)) > t.config.JSONMaxBytes {
		return ErrBodyTooLarge
	}
	// Bound all metadata before URL escaping, header formatting or allocation.
	left := t.config.HeaderMaxBytes
	consume := func(s string) bool {
		if int64(len(s)) > left {
			return false
		}
		left -= int64(len(s))
		return true
	}
	for _, value := range []string{r.Owner, r.Bucket, r.Path, r.Method, r.Authorization} {
		if !consume(value) {
			return ErrHeadersTooLarge
		}
	}
	if r.AuditReason != nil && !consume(*r.AuditReason) {
		return ErrHeadersTooLarge
	}
	if r.Locale != nil && !consume(*r.Locale) {
		return ErrHeadersTooLarge
	}
	for key, values := range r.Query {
		if len(values) == 0 && !consume(key) {
			return ErrHeadersTooLarge
		}
		for _, value := range values {
			if !consume(key) || !consume(value) || left < 2 {
				return ErrHeadersTooLarge
			}
			left -= 2
		}
	}
	if int64(len(r.Files)) > left {
		return ErrHeadersTooLarge
	}
	for i, file := range r.Files {
		if !consume(file.Name) || !consume(file.Filename) || !consume(file.ContentType) {
			return ErrHeadersTooLarge
		}
		if file.Name != "files["+strconv.Itoa(i)+"]" || file.Filename == "" || !cleanText(file.Filename) || !cleanText(file.ContentType) || file.Size < 0 || file.Open == nil {
			return ErrInvalidRequest
		}
		media, params, err := mime.ParseMediaType(file.ContentType)
		if err != nil || media == "" || strings.HasPrefix(media, "multipart/") || mime.FormatMediaType(media, params) == "" {
			return ErrInvalidRequest
		}
	}
	switch r.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return ErrInvalidRequest
	}
	if !cleanText(r.Authorization) || (r.AuditReason != nil && !cleanText(*r.AuditReason)) || (r.Locale != nil && !cleanText(*r.Locale)) {
		return ErrInvalidRequest
	}
	if !strings.HasPrefix(r.Path, "/api/v10/") || strings.HasPrefix(r.Path, "//") || strings.ContainsAny(r.Path, "\\?#") || !cleanText(r.Path) {
		return ErrInvalidRequest
	}
	target, err := url.ParseRequestURI(r.Path)
	if err != nil || target.IsAbs() || target.Host != "" || target.RawQuery != "" || target.Fragment != "" || !cleanText(target.Path) {
		return ErrInvalidRequest
	}
	for _, part := range strings.Split(target.Path, "/") {
		if part == "." || part == ".." || strings.ContainsAny(part, "\\\x00\r\n") {
			return ErrInvalidRequest
		}
	}
	return nil
}

type preparedRequest struct {
	target   string
	header   http.Header
	length   int64
	json     []byte
	files    []File
	boundary string
	parts    [][]byte
	closing  []byte
}

func (t *Transport) prepare(r Request) (*preparedRequest, error) {
	query := r.Query.Encode()
	if int64(len(query)) > t.config.HeaderMaxBytes {
		return nil, ErrHeadersTooLarge
	}
	target := "https://discord.com" + r.Path
	if query != "" {
		target += "?" + query
	}
	if int64(len(target)) > t.config.HeaderMaxBytes {
		return nil, ErrHeadersTooLarge
	}
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	if r.Authorization != "" {
		header.Set("Authorization", r.Authorization)
	}
	if r.AuditReason != nil {
		header.Set("X-Audit-Log-Reason", url.QueryEscape(*r.AuditReason))
	}
	if r.Locale != nil {
		header.Set("X-Discord-Locale", *r.Locale)
	}
	p := &preparedRequest{target: target, header: header, json: r.JSON, files: r.Files, length: int64(len(r.JSON))}
	if len(r.Files) != 0 {
		parts := make([]textproto.MIMEHeader, 0, len(r.Files)+1)
		parts = append(parts, textproto.MIMEHeader{"Content-Disposition": {`form-data; name="payload_json"`}, "Content-Type": {"application/json"}})
		totalHeaders := headerSize(http.Header(parts[0]), t.config.HeaderMaxBytes)
		if totalHeaders < 0 {
			return nil, ErrHeadersTooLarge
		}
		for _, file := range r.Files {
			disposition := mime.FormatMediaType("form-data", map[string]string{"name": file.Name, "filename": file.Filename})
			if disposition == "" {
				return nil, ErrInvalidRequest
			}
			h := textproto.MIMEHeader{"Content-Disposition": {disposition}, "Content-Type": {file.ContentType}}
			size := headerSize(http.Header(h), t.config.HeaderMaxBytes-totalHeaders)
			if size < 0 {
				return nil, ErrHeadersTooLarge
			}
			totalHeaders += size
			parts = append(parts, h)
		}
		boundary, err := newMultipartBoundary()
		if err != nil {
			return nil, err
		}
		p.boundary = boundary
		p.parts = make([][]byte, len(parts))
		for i, part := range parts {
			prefix := "--"
			if i != 0 {
				prefix = "\r\n--"
			}
			// These validated, fixed header names are the complete part
			// catalog. Count and transmit the same retained framing bytes.
			p.parts[i] = []byte(prefix + boundary + "\r\nContent-Disposition: " + part.Get("Content-Disposition") + "\r\nContent-Type: " + part.Get("Content-Type") + "\r\n\r\n")
		}
		p.closing = []byte("\r\n--" + boundary + "--\r\n")
		length, err := p.multipartLength(r.MaxBodyBytes)
		if err != nil {
			return nil, err
		}
		p.length = length
		header.Set("Content-Type", "multipart/form-data; boundary="+p.boundary)
	}
	header.Set("Content-Length", strconv.FormatInt(p.length, 10))
	if headerSize(header, t.config.HeaderMaxBytes) < 0 {
		return nil, ErrHeadersTooLarge
	}
	if p.length > r.MaxBodyBytes {
		return nil, ErrBodyTooLarge
	}
	return p, nil
}

func (p *preparedRequest) jsonBody() io.ReadCloser {
	if len(p.json) == 0 {
		return http.NoBody
	}
	return io.NopCloser(bytes.NewReader(p.json))
}
