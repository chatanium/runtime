package bootstrap

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
)

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)

func validID(s string) bool { return identifier.MatchString(s) }
func newID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
func digest(domain string, v any) (string, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	if len(raw) > WorkerControlMaxBytes {
		return "", errors.New("approval exceeds bound")
	}
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(raw)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
func approvalDigest(domain string, v any, field string) (string, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	var payload map[string]json.RawMessage
	if e = json.Unmarshal(raw, &payload); e != nil {
		return "", e
	}
	delete(payload, field)
	return digest(domain, payload)
}
func InitPlanDigest(p ApprovedInitPlan) (string, error) {
	return approvalDigest("chatanium-init-plan-v1", p, "plan_digest")
}
func PurgePlanDigest(p PurgeApproval) (string, error) {
	return approvalDigest("chatanium-purge-plan-v1", p, "plan_digest")
}
func UpdatePlanDigest(p ApprovedUpdatePlan) (string, error) {
	return approvalDigest("chatanium-update-plan-v1", p, "plan_digest")
}
func ModuleReviewDigest(p ModuleReview) (string, error) {
	return approvalDigest("chatanium-module-review-v1", p, "review_digest")
}
func ValidateModuleApproval(r ModuleReview, a ApprovedModuleConfig) error {
	d, e := ModuleReviewDigest(r)
	if e != nil {
		return e
	}
	if r.ReviewDigest != d || a.ReviewDigest != d || a.ImageRecordID != r.Image.ID || a.ImageRevision != r.Image.Revision {
		return errors.New("module approval review mismatch")
	}
	x, y := r.Candidate, a.Module
	x.Approval = nil
	y.Approval = nil
	x.CredentialBindings = nil
	y.CredentialBindings = nil
	if !reflect.DeepEqual(x, y) {
		return errors.New("module approval changes inspected candidate")
	}
	if a.Module.Approval == nil || a.Module.Approval.ResourceLimits == nil {
		return errors.New("explicit grants required")
	}
	var m wire.ModuleManifest
	if e = protojson.Unmarshal(r.Image.Declaration, &m); e != nil {
		return e
	}
	if m.ProtocolMajor != 2 {
		return errors.New("unsupported module protocol")
	}
	return nil
}
func controlPath(id RuntimeInstallationID) (string, error) {
	if !validID(string(id)) {
		return "", errors.New("invalid installation ID")
	}
	return filepath.Join("/var/lib/chatanium/installations", string(id), "control"), nil
}
func rootRequired() error {
	if os.Geteuid() != 0 {
		return errors.New("host root privilege required")
	}
	return nil
}
func trustedPath(path string, missing bool) error {
	if path == "/" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		return errors.New("absolute protected path required")
	}
	current := "/"
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for n, s := range parts {
		current = filepath.Join(current, s)
		var st unix.Stat_t
		e := unix.Lstat(current, &st)
		if e != nil {
			if missing && n == len(parts)-1 && errors.Is(e, unix.ENOENT) {
				return nil
			}
			return e
		}
		if st.Uid != 0 || st.Mode&0022 != 0 || st.Mode&unix.S_IFMT == unix.S_IFLNK {
			return fmt.Errorf("untrusted path %s", current)
		}
		if n < len(parts)-1 && st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return errors.New("path ancestor is not directory")
		}
	}
	return nil
}
func readProtected(path string, max int64) ([]byte, error) {
	if e := trustedPath(path, false); e != nil {
		return nil, e
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return nil, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size < 0 || st.Size > max {
		return nil, errors.New("invalid protected regular file")
	}
	raw := make([]byte, st.Size)
	_, e = f.ReadAt(raw, 0)
	return raw, e
}
func exactConfig(base []byte, modules []runtime.ModuleSpec) ([]byte, error) {
	c, e := runtime.DecodeConfig(base)
	if e != nil {
		return nil, e
	}
	c.Modules = modules
	if e = c.Validate(); e != nil {
		return nil, e
	}
	var doc map[string]json.RawMessage
	if e = json.Unmarshal(base, &doc); e != nil {
		return nil, e
	}
	out := make([]json.RawMessage, 0, len(modules))
	for _, m := range modules {
		approval, e := protojson.Marshal(m.Approval)
		if e != nil {
			return nil, e
		}
		v := struct {
			ModuleID         runtime.ModuleID                       `json:"module_id"`
			Image            string                                 `json:"image"`
			Entrypoint       []string                               `json:"entrypoint"`
			Args             []string                               `json:"args"`
			UID              uint32                                 `json:"uid"`
			GID              uint32                                 `json:"gid"`
			Config           json.RawMessage                        `json:"config"`
			Approval         json.RawMessage                        `json:"approval"`
			Bindings         []runtime.ProvisionedCredentialBinding `json:"credential_bindings"`
			ConfigRevision   string                                 `json:"config_revision"`
			ApprovalRevision string                                 `json:"approval_revision"`
		}{m.ModuleID, m.ImageDigest, m.Entrypoint, m.Args, m.UID, m.GID, m.Config.Json, approval, m.CredentialBindings, m.ConfigRevision, m.ApprovalRevision}
		raw, e := json.Marshal(v)
		if e != nil {
			return nil, e
		}
		out = append(out, raw)
	}
	doc["modules"], e = json.Marshal(out)
	if e != nil {
		return nil, e
	}
	raw, e := json.Marshal(doc)
	if e != nil {
		return nil, e
	}
	if _, e = runtime.DecodeConfig(raw); e != nil {
		return nil, e
	}
	return bytes.Clone(raw), nil
}
func provisionJSON(p host.ProvisionProperties) []byte { b, _ := json.Marshal(p); return b }
