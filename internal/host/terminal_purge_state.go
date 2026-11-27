//go:build linux

package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/provision"
	"golang.org/x/sys/unix"
)

type TerminalObject struct {
	RecordID string                 `json:"record_id"`
	Name     string                 `json:"name"`
	Native   TerminalNativeIdentity `json:"native"`
}
type TerminalGuard struct {
	Kind      string `json:"kind"`
	RecordID  string `json:"record_id"`
	Path      string `json:"path"`
	Name      string `json:"name"`
	UUID      string `json:"uuid"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	GroupOnly bool   `json:"group_only,omitempty"`
}
type TerminalPurgeSeal struct {
	Version        uint32                 `json:"version"`
	InstallationID string                 `json:"installation_id"`
	Incarnation    string                 `json:"incarnation"`
	TransactionID  string                 `json:"transaction_id"`
	ApprovalDigest string                 `json:"approval_digest"`
	ApprovedPlan   []byte                 `json:"approved_plan"`
	ReceiptPath    string                 `json:"receipt_path"`
	SourceControl  TerminalNativeIdentity `json:"source_control"`
	SourceDatabase TerminalNativeIdentity `json:"source_database"`
	FrozenManifest TerminalNativeIdentity `json:"frozen_manifest"`
	Remaining      []TerminalObject       `json:"remaining"`
	AbsenceGuards  []TerminalGuard        `json:"absence_guards"`
}
type TerminalFence struct {
	Version        uint32                 `json:"version"`
	InstallationID string                 `json:"installation_id"`
	Incarnation    string                 `json:"incarnation"`
	TransactionID  string                 `json:"transaction_id"`
	ApprovalDigest string                 `json:"approval_digest"`
	ScopeDigest    string                 `json:"scope_digest"`
	ReceiptPath    string                 `json:"receipt_path"`
	SourceControl  TerminalNativeIdentity `json:"source_control"`
	SourceDatabase TerminalNativeIdentity `json:"source_database"`
	FrozenManifest TerminalNativeIdentity `json:"frozen_manifest"`
	ApprovedPlan   []byte                 `json:"approved_plan"`
	Remaining      []TerminalObject       `json:"remaining"`
	AbsenceGuards  []TerminalGuard        `json:"absence_guards"`
	Frozen         bool                   `json:"frozen"`
	Cleanup        CleanupEvidence        `json:"cleanup"`
}
type TerminalProbeRecord struct {
	Version        uint32                    `json:"version"`
	InstallationID string                    `json:"installation_id"`
	Incarnation    string                    `json:"incarnation"`
	TransactionID  string                    `json:"transaction_id"`
	ApprovalDigest string                    `json:"approval_digest"`
	ApprovedPlan   []byte                    `json:"approved_plan"`
	Attempt        uint64                    `json:"attempt"`
	Paths          [2]string                 `json:"paths"`
	Files          [2]TerminalNativeIdentity `json:"files"`
	Payloads       [2][]byte                 `json:"payloads"`
	Complete       bool                      `json:"complete"`
	Exchanged      bool                      `json:"exchanged"`
}
type TerminalProbeEvidence struct {
	CreatedAnonymous  bool
	LinkedNoReplace   bool
	NoReplaceRejected bool
	Exchanged         bool
	Synced            bool
	Absent            bool
}
type TerminalCapability struct {
	InstallationID, Incarnation, TransactionID, ApprovalDigest string
	Attempt, RootDevice, RootInode                             uint64
}
type TerminalPublicationBinding struct {
	Attempt       uint64                 `json:"attempt"`
	Seal          TerminalPurgeSeal      `json:"seal"`
	SealDigest    string                 `json:"seal_digest"`
	Payload       []byte                 `json:"payload"`
	PayloadDigest string                 `json:"payload_digest"`
	Native        TerminalNativeIdentity `json:"native"`
}

const terminalJSONMax = 32 << 20

func terminalKeyID(txn string) bool { _, err := managementKey("init", txn); return err == nil }
func terminalReadRecord(ctx context.Context, s *Store, key string, destination any) error {
	var raw []byte
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", key).Scan(&raw); err != nil {
		return err
	}
	return gvxcontract.DecodeStrict(raw, terminalJSONMax, 48, destination)
}
func terminalWriteRecord(ctx context.Context, s *Store, key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(raw) > terminalJSONMax {
		return invalid("terminal source record exceeds bound")
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO metadata VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, raw)
	return err
}
func terminalObserve(path string, digest bool) (TerminalNativeIdentity, error) {
	var stat unix.Stat_t
	err := unix.Lstat(path, &stat)
	if errors.Is(err, unix.ENOENT) {
		return TerminalNativeIdentity{Path: path, Absent: true}, nil
	}
	if err != nil {
		return TerminalNativeIdentity{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG && stat.Mode&unix.S_IFMT != unix.S_IFDIR && stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return TerminalNativeIdentity{}, errors.New("terminal native object is not a permitted type")
	}
	result := nativeManagementIdentity(path, stat)
	if digest {
		if result.Kind != "file" || result.Links != 1 {
			return result, errors.New("terminal stable content requires single-link regular file")
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return result, err
		}
		file := os.NewFile(uintptr(fd), "terminal-stable-witness")
		var pinned unix.Stat_t
		if err = unix.Fstat(fd, &pinned); err != nil {
			file.Close()
			return result, err
		}
		if nativeManagementIdentity(path, pinned) != result {
			file.Close()
			return result, errors.New("terminal witness opened a different inode")
		}
		raw, err := io.ReadAll(io.LimitReader(file, durableJSONMax+1))
		file.Close()
		if err != nil {
			return result, err
		}
		if len(raw) > durableJSONMax {
			return result, errors.New("stable terminal witness exceeds bound")
		}
		var readStat unix.Stat_t
		if err = unix.Lstat(path, &readStat); err != nil {
			return result, err
		}
		if nativeManagementIdentity(path, readStat) != result {
			return result, errors.New("terminal witness identity changed while reading")
		}
		result.Digest = provision.Digest(raw)
	}
	return result, nil
}
func terminalIdentityMatches(expected, actual TerminalNativeIdentity, allowAbsent bool) bool {
	if actual.Absent {
		return allowAbsent || expected.Absent
	}
	return !expected.Absent && expected.Path == actual.Path && expected.Kind == actual.Kind && expected.Device == actual.Device && expected.Inode == actual.Inode && expected.UID == actual.UID && expected.GID == actual.GID && expected.Mode == actual.Mode && expected.Links == actual.Links && (expected.Digest == "" || expected.Digest == actual.Digest)
}
func (s *Store) terminalAuthority(g *ManagementGuard) error {
	if err := g.require(true); err != nil {
		return err
	}
	if s.gate != g || s.closed {
		return ErrManagementGuardRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.installationLease == nil || s.installationLease.closed {
		return errors.New("terminal source requires continuously held installation lease")
	}
	if err := g.checkNoReceipt(s.productID); err != nil {
		return err
	}
	return s.checkSourceAdmission(context.Background(), s.terminalOnly)
}
func terminalApproval(raw []byte, id string) (string, string, []struct {
	Kind              string `json:"kind"`
	Identity          string `json:"identity"`
	Action            string `json:"action"`
	ObservationDigest string `json:"observation_digest"`
}, error) {
	var value any
	if err := gvxcontract.DecodeStrict(raw, managementPlanBytesMax, 32, &value); err != nil {
		return "", "", nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return "", "", nil, err
	}
	var installation, planID, digest string
	if err := json.Unmarshal(fields["installation_id"], &installation); err != nil || installation != id {
		return "", "", nil, invalid("terminal approval installation differs")
	}
	if err := json.Unmarshal(fields["plan_id"], &planID); err != nil || !terminalKeyID(planID) {
		return "", "", nil, invalid("terminal approval plan identity differs")
	}
	if err := json.Unmarshal(fields["plan_digest"], &digest); err != nil {
		return "", "", nil, err
	}
	delete(fields, "plan_digest")
	canonical, err := json.Marshal(fields)
	if err != nil {
		return "", "", nil, err
	}
	if provision.DomainDigest("chatanium-purge-plan-v1", canonical) != digest {
		return "", "", nil, invalid("terminal approved plan digest differs")
	}
	var scope []struct {
		Kind              string `json:"kind"`
		Identity          string `json:"identity"`
		Action            string `json:"action"`
		ObservationDigest string `json:"observation_digest"`
	}
	if err = json.Unmarshal(fields["scope"], &scope); err != nil {
		return "", "", nil, err
	}
	if len(scope) == 0 || len(scope) > 4096 {
		return "", "", nil, invalid("terminal purge requires finite explicit scope")
	}
	return planID, digest, scope, nil
}
func (s *Store) TerminalPublicationProbe(ctx context.Context, txnID string) (TerminalProbeRecord, error) {
	var record TerminalProbeRecord
	if !terminalKeyID(txnID) {
		return record, invalid("invalid terminal transaction identity")
	}
	err := terminalReadRecord(ctx, s, "terminal_probe:"+txnID, &record)
	return record, err
}
func (s *Store) TerminalPurgeFence(ctx context.Context) (TerminalFence, error) {
	var fence TerminalFence
	err := terminalReadRecord(ctx, s, "terminal_fence", &fence)
	return fence, err
}
func (s *Store) TerminalPurgePublication(ctx context.Context) (TerminalPublicationBinding, error) {
	var binding TerminalPublicationBinding
	err := terminalReadRecord(ctx, s, "terminal_publication", &binding)
	return binding, err
}
func terminalAnonymous(file *os.File, payload []byte, path string, uid uint32) (TerminalNativeIdentity, error) {
	if file == nil || len(payload) == 0 || len(payload) > terminalJSONMax {
		return TerminalNativeIdentity{}, invalid("complete anonymous terminal payload required")
	}
	var value any
	if err := gvxcontract.DecodeStrict(payload, terminalJSONMax, 48, &value); err != nil {
		return TerminalNativeIdentity{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return TerminalNativeIdentity{}, err
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return TerminalNativeIdentity{}, err
	}
	if flags&unix.O_TMPFILE != unix.O_TMPFILE || stat.Nlink != 0 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uid || stat.Gid != uid || stat.Mode&07777 != 0600 || stat.Size != int64(len(payload)) {
		return TerminalNativeIdentity{}, errors.New("terminal publication is not a protected complete anonymous inode")
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return TerminalNativeIdentity{}, err
	}
	actual, err := io.ReadAll(io.LimitReader(file, int64(len(payload))+1))
	if err != nil {
		return TerminalNativeIdentity{}, err
	}
	if !bytes.Equal(actual, payload) {
		return TerminalNativeIdentity{}, errors.New("anonymous terminal payload differs from exact source bytes")
	}
	if err = file.Sync(); err != nil {
		return TerminalNativeIdentity{}, err
	}
	identity := nativeManagementIdentity(path, stat)
	identity.Digest = provision.Digest(payload)
	return identity, nil
}

func (s *Store) ActiveTerminalPublicationProbe(ctx context.Context) (TerminalProbeRecord, error) {
	var txn string
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='terminal_probe_active'").Scan(&txn); err != nil {
		return TerminalProbeRecord{}, err
	}
	return s.TerminalPublicationProbe(ctx, txn)
}
func terminalProbeAbsent(g *ManagementGuard, record TerminalProbeRecord) error {
	for _, path := range record.Paths {
		rootFD, err := g.RootFD()
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		err = unix.Fstatat(rootFD, filepath.Base(path), &stat, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			return errors.New("terminal probe stage is present or has reappeared")
		}
		if !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	return nil
}
func (s *Store) BindTerminalPublicationProbe(ctx context.Context, g *ManagementGuard, approvalRaw []byte, txnID string, files [2]*os.File, payloads [2][]byte, expectedAttempt uint64) (TerminalProbeRecord, error) {
	var record TerminalProbeRecord
	if err := s.terminalAuthority(g); err != nil {
		return record, err
	}
	planID, digest, _, err := terminalApproval(approvalRaw, s.productID)
	if err != nil {
		return record, err
	}
	if txnID != planID {
		return record, invalid("terminal transaction must be original approved plan identity")
	}
	record = TerminalProbeRecord{Version: 1, InstallationID: s.productID, Incarnation: s.incarnation, TransactionID: txnID, ApprovalDigest: digest, ApprovedPlan: append([]byte(nil), approvalRaw...), Attempt: expectedAttempt + 1, Payloads: payloads}
	if expectedAttempt == ^uint64(0) {
		return record, errors.New("terminal probe attempt exhausted")
	}
	for index := range files {
		record.Paths[index], err = g.stagePath(s.productID, txnID, uint64(index))
		if err != nil {
			return record, err
		}
		record.Files[index], err = terminalAnonymous(files[index], payloads[index], record.Paths[index], g.uid)
		if err != nil {
			return record, err
		}
		record.Files[index].Links = 1
	}
	if record.Files[0].Device != record.Files[1].Device || record.Files[0].Inode == record.Files[1].Inode {
		return record, invalid("capability probes require distinct native objects on the management filesystem")
	}
	if err = terminalProbeAbsent(g, record); err != nil {
		return record, err
	}
	rootFD, err := g.RootFD()
	if err != nil {
		return record, err
	}
	var root unix.Stat_t
	if err = unix.Fstat(rootFD, &root); err != nil {
		return record, err
	}
	if uint64(root.Dev) != record.Files[0].Device {
		return record, errors.New("terminal probe anonymous inode is on another filesystem")
	}
	controlFD, err := unix.Open(s.dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return record, err
	}
	witnessFD, err := unix.Openat(controlFD, ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	unix.Close(controlFD)
	if err != nil {
		return record, err
	}
	witness := os.NewFile(uintptr(witnessFD), "terminal-witness-capability")
	if _, err = witness.WriteString("chatanium-terminal-witness-capability-v1\n"); err == nil {
		err = witness.Sync()
	}
	err = errors.Join(err, witness.Close())
	if err != nil {
		return record, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return record, err
	}
	defer tx.Rollback()
	var active string
	err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='terminal_probe_active'").Scan(&active)
	if err == nil && active != txnID {
		return record, errors.New("another exact purge approval is already in progress")
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return record, err
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", "terminal_probe:"+txnID).Scan(&raw)
	if err == nil {
		var old TerminalProbeRecord
		if err = gvxcontract.DecodeStrict(raw, terminalJSONMax, 48, &old); err != nil {
			return record, err
		}
		if old.Attempt != expectedAttempt || old.Complete || old.Incarnation != record.Incarnation || old.ApprovalDigest != digest || !bytes.Equal(old.ApprovedPlan, approvalRaw) {
			return record, errors.New("terminal probe attempt compare-and-swap or original approval mismatch")
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		if expectedAttempt != 0 {
			return record, errors.New("terminal probe missing expected attempt")
		}
	} else {
		return record, err
	}
	raw, err = json.Marshal(record)
	if err != nil {
		return record, err
	}
	if len(raw) > terminalJSONMax {
		return record, invalid("terminal probe record exceeds bound")
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO metadata VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", "terminal_probe:"+txnID, raw); err != nil {
		return record, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO metadata VALUES('terminal_probe_active',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", txnID); err != nil {
		return record, err
	}
	if err = tx.Commit(); err != nil {
		return record, err
	}
	return record, nil
}
func (s *Store) ValidateTerminalPublicationProbe(ctx context.Context, g *ManagementGuard, record TerminalProbeRecord) error {
	if err := s.terminalAuthority(g); err != nil {
		return err
	}
	stored, err := s.ActiveTerminalPublicationProbe(ctx)
	if err != nil {
		return err
	}
	want, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	got, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if !bytes.Equal(want, got) || record.InstallationID != s.productID || record.Incarnation != s.incarnation || record.Version != 1 {
		return errors.New("terminal probe recovery is not the exact active source attempt")
	}
	return nil
}
func (s *Store) RecordTerminalPublicationProbeExchange(ctx context.Context, g *ManagementGuard, record TerminalProbeRecord, e TerminalProbeEvidence) (TerminalProbeRecord, error) {
	if err := s.ValidateTerminalPublicationProbe(ctx, g, record); err != nil {
		return record, err
	}
	if !e.CreatedAnonymous || !e.LinkedNoReplace || !e.NoReplaceRejected || !e.Exchanged || !e.Synced || record.Complete {
		return record, errors.New("terminal capability exchange evidence is incomplete")
	}
	for index, path := range record.Paths {
		actual, err := terminalObserve(path, true)
		if err != nil {
			return record, err
		}
		expected := record.Files[1-index]
		expected.Path = path
		if !terminalIdentityMatches(expected, actual, false) {
			return record, errors.New("capability exchange did not produce exact swapped native objects")
		}
	}
	record.Exchanged = true
	if err := terminalWriteRecord(ctx, s, "terminal_probe:"+record.TransactionID, record); err != nil {
		return record, err
	}
	return record, nil
}
func (s *Store) CompleteTerminalPublicationProbe(ctx context.Context, g *ManagementGuard, record TerminalProbeRecord, e TerminalProbeEvidence) (TerminalCapability, error) {
	var cap TerminalCapability
	if err := s.ValidateTerminalPublicationProbe(ctx, g, record); err != nil {
		return cap, err
	}
	if !record.Exchanged || !e.CreatedAnonymous || !e.LinkedNoReplace || !e.NoReplaceRejected || !e.Exchanged || !e.Synced || !e.Absent {
		return cap, errors.New("terminal capability probe is not durably exchanged and absent")
	}
	if err := terminalProbeAbsent(g, record); err != nil {
		return cap, err
	}
	rootFD, err := g.RootFD()
	if err != nil {
		return cap, err
	}
	var root unix.Stat_t
	if err = unix.Fstat(rootFD, &root); err != nil {
		return cap, err
	}
	record.Complete = true
	if err = terminalWriteRecord(ctx, s, "terminal_probe:"+record.TransactionID, record); err != nil {
		return cap, err
	}
	return TerminalCapability{InstallationID: record.InstallationID, Incarnation: record.Incarnation, TransactionID: record.TransactionID, ApprovalDigest: record.ApprovalDigest, Attempt: record.Attempt, RootDevice: uint64(root.Dev), RootInode: root.Ino}, nil
}
func (s *Store) validateTerminalCapability(ctx context.Context, g *ManagementGuard, cap TerminalCapability) (TerminalProbeRecord, error) {
	record, err := s.ActiveTerminalPublicationProbe(ctx)
	if err != nil {
		return record, err
	}
	if err = s.ValidateTerminalPublicationProbe(ctx, g, record); err != nil {
		return record, err
	}
	rootFD, err := g.RootFD()
	if err != nil {
		return record, err
	}
	var root unix.Stat_t
	if err = unix.Fstat(rootFD, &root); err != nil {
		return record, err
	}
	if !record.Complete || !record.Exchanged || cap.InstallationID != record.InstallationID || cap.Incarnation != record.Incarnation || cap.TransactionID != record.TransactionID || cap.ApprovalDigest != record.ApprovalDigest || cap.Attempt != record.Attempt || cap.RootDevice != uint64(root.Dev) || cap.RootInode != root.Ino {
		return record, errors.New("terminal capability is not the completed source-bound probe")
	}
	return record, terminalProbeAbsent(g, record)
}
func (s *Store) RetireTerminalPublicationProbe(ctx context.Context, g *ManagementGuard, cap TerminalCapability) error {
	record, err := s.validateTerminalCapability(ctx, g, cap)
	if err != nil {
		return err
	}
	if _, err = s.TerminalPurgeFence(ctx); err == nil {
		return ErrTerminalPurge
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, _, scope, err := terminalApproval(record.ApprovedPlan, s.productID)
	if err != nil {
		return err
	}
	for _, object := range scope {
		if object.Action != "remove" && object.Action != "delete" {
			continue
		}
		var count int
		if err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM provisioning_ledger WHERE kind=? AND identity=?", object.Kind, object.Identity).Scan(&count); err != nil {
			return err
		}
		if count == 0 {
			return errors.New("partial purge scope lacks authoritative completed lineage")
		}
		records, err := s.ObjectProvisions(ctx, object.Kind, object.Identity)
		if err != nil {
			return err
		}
		completed := false
		for _, item := range records {
			completed = completed || item.CleanupState == "COMPLETE"
		}
		if !completed {
			return errors.New("partial purge selected object remains incomplete")
		}
	}
	_, err = s.db.ExecContext(ctx, "DELETE FROM metadata WHERE key='terminal_probe_active' AND value=?", record.TransactionID)
	return err
}

func terminalSameJSON(a, b any) bool {
	left, err := json.Marshal(a)
	if err != nil {
		return false
	}
	right, err := json.Marshal(b)
	return err == nil && bytes.Equal(left, right)
}
func terminalScopeContains(scope []struct {
	Kind              string `json:"kind"`
	Identity          string `json:"identity"`
	Action            string `json:"action"`
	ObservationDigest string `json:"observation_digest"`
}, kind, path string) bool {
	for _, object := range scope {
		if object.Kind == kind && object.Identity == path {
			return true
		}
	}
	return false
}
func (s *Store) validateTerminalObjects(ctx context.Context, approval []byte, remaining []TerminalObject, guards []TerminalGuard) error {
	_, _, scope, err := terminalApproval(approval, s.productID)
	if err != nil {
		return err
	}
	if !terminalScopeContains(scope, "directory", s.dir) || len(remaining) == 0 || len(remaining) > 4096 || len(guards) > 8192 {
		return invalid("terminal scope must select its finite owned control closure")
	}
	manifest, err := s.Installation(ctx)
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, name := range []string{"runtime.sock", "management.sock", "installation.json.next", "supervisor.sqlite-wal", "supervisor.sqlite-shm", "supervisor.sqlite", "installation.json", "installation.lock"} {
		allowed[filepath.Join(s.dir, name)] = true
	}
	allowed[s.dir] = true
	seen := map[string]bool{}
	for _, object := range remaining {
		path := object.Native.Path
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == s.gate.root || path == filepath.Dir(s.gate.root) || seen[path] {
			return invalid("terminal remaining object is not a unique canonical scoped path")
		}
		seen[path] = true
		if !allowed[path] {
			if !terminalScopeContains(scope, "directory", path) || path == "/" || !strings.HasPrefix(s.dir, path+string(os.PathSeparator)) {
				return invalid("terminal object is not a selected owned control ancestor")
			}
			history, err := s.ObjectProvisions(ctx, "directory", path)
			if err != nil {
				return err
			}
			owned := false
			for _, record := range history {
				owned = owned || record.State == "OBSERVED" && record.ProductCreated && !record.ExistedBefore && record.CleanupState != "COMPLETE"
			}
			if !owned {
				return errors.New("terminal ancestor has no current owned journal lineage")
			}
		}
		stable := object.Native.Digest != "" && path != filepath.Join(s.dir, "supervisor.sqlite") && !strings.HasSuffix(path, "-wal") && !strings.HasSuffix(path, "-shm")
		actual, err := terminalObserve(path, stable)
		if err != nil {
			return err
		}
		if !terminalIdentityMatches(object.Native, actual, false) {
			return errors.New("terminal remaining native identity differs from observed source")
		}
		if !actual.Absent {
			if actual.Kind == "socket" {
				if path == filepath.Join(s.dir, "runtime.sock") {
					if actual.UID != s.gate.uid || actual.GID != manifest.Identities.App.GID || actual.Mode != 0660 || actual.Links != 1 {
						return errors.New("runtime terminal socket differs from exact root/app native identity")
					}
				} else if path != filepath.Join(s.dir, "management.sock") || actual.UID != s.gate.uid || actual.GID != s.gate.uid || actual.Mode != 0600 || actual.Links != 1 {
					return errors.New("management terminal socket differs from exact root-private identity")
				}
			} else if actual.UID != s.gate.uid || actual.Mode&0022 != 0 || actual.Kind == "file" && (actual.GID != s.gate.uid || actual.Mode != 0600 || actual.Links != 1) {
				return errors.New("terminal remaining object is not protected owned metadata")
			}
		}
	}
	if !seen[s.dir] || !seen[filepath.Join(s.dir, "supervisor.sqlite")] || !seen[filepath.Join(s.dir, "installation.json")] {
		return invalid("terminal scope omits required source authority objects")
	}
	for _, object := range remaining {
		if object.Native.Absent || object.Native.Kind != "directory" {
			continue
		}
		entries, err := os.ReadDir(object.Native.Path)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !seen[filepath.Join(object.Native.Path, entry.Name())] {
				return errors.New("terminal directory has an unselected or foreign child")
			}
		}
	}
	guarded := map[string]bool{}
	for _, guard := range guards {
		if guard.Kind != "path" && guard.Kind != "account" || !validLedgerID(guard.RecordID) {
			return invalid("unknown historical terminal absence guard")
		}
		record, err := s.Provision(ctx, guard.RecordID)
		if err != nil {
			return err
		}
		if record.State != "OBSERVED" || record.CleanupState != "COMPLETE" || !record.ProductCreated || record.ExistedBefore {
			return errors.New("terminal absence guard lacks completed original ownership")
		}
		var properties ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &properties); err != nil {
			return err
		}
		if guard.Kind == "account" {
			if record.Kind != "account" {
				return errors.New("terminal account guard lacks original account ownership")
			}
			if err := validateTerminalAccountGuardSource(guard, properties); err != nil {
				return err
			}
		} else {
			if guard.GroupOnly {
				return invalid("terminal path guard cannot carry account disposition")
			}
			path := properties.Path
			if record.Kind == "mount" {
				path = properties.Target
			}
			if path == "" {
				path = record.Identity
			}
			if guard.Path != path || !filepath.IsAbs(path) || seen[path] {
				return errors.New("terminal path guard differs from completed original object")
			}
			actual, err := terminalObserve(path, false)
			if err != nil {
				return err
			}
			if !actual.Absent {
				return errors.New("completed selected path has reappeared")
			}
		}
		guarded[record.Kind+":"+record.Identity] = true
	}
	for _, object := range scope {
		if seen[object.Identity] || object.Kind == "management-anchor" || object.Kind == "shared-network-anchor" {
			continue
		}
		if !guarded[object.Kind+":"+object.Identity] {
			manifest, err := s.Installation(ctx)
			if err != nil {
				return err
			}
			if manifest.Paths.StorageRoot != "" && (object.Identity == manifest.Paths.StorageRoot || strings.HasPrefix(object.Identity, manifest.Paths.StorageRoot+string(os.PathSeparator))) {
				continue
			}
			return errors.New("terminal authority omits completed selected payload/account absence guard")
		}
	}
	return nil
}
func (s *Store) PrepareTerminalPurge(ctx context.Context, g *ManagementGuard, cap TerminalCapability, approvalRaw []byte, txnID string, e CleanupEvidence, remaining []TerminalObject, guards []TerminalGuard) (TerminalFence, error) {
	var fence TerminalFence
	if err := s.terminalAuthority(g); err != nil {
		return fence, err
	}
	probe, err := s.validateTerminalCapability(ctx, g, cap)
	if err != nil {
		return fence, err
	}
	if probe.TransactionID != txnID || !bytes.Equal(probe.ApprovedPlan, approvalRaw) {
		return fence, errors.New("terminal fence differs from preflight original approval")
	}
	if existing, err := s.TerminalPurgeFence(ctx); err == nil {
		if existing.TransactionID != txnID || existing.ApprovalDigest != probe.ApprovalDigest || !bytes.Equal(existing.ApprovedPlan, approvalRaw) {
			return fence, ErrTerminalPurge
		}
		return s.finishTerminalFreeze(ctx, g, existing)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fence, err
	}
	if err = validateCleanup(e); err != nil {
		return fence, err
	}
	if err = s.validateTerminalObjects(ctx, approvalRaw, remaining, guards); err != nil {
		return fence, err
	}
	m, err := s.Installation(ctx)
	if err != nil {
		return fence, err
	}
	if m.DesiredRunState != "STOPPED" {
		return fence, errors.New("terminal purge requires stopped desired intent")
	}
	var unfinished int
	if err = s.db.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM instances WHERE cleanup!='COMPLETE')+(SELECT count(*) FROM create_submissions WHERE state='SUBMITTED')+(SELECT count(*) FROM storage_claims WHERE kind IN ('scratch','preparation') AND state!='RELEASED')+(SELECT count(*) FROM generation_references WHERE kind IN ('live','preparation'))").Scan(&unfinished); err != nil {
		return fence, err
	}
	if unfinished != 0 {
		return fence, ErrCleanupIncomplete
	}
	_, _, scope, err := terminalApproval(approvalRaw, s.productID)
	if err != nil {
		return fence, err
	}
	scopeRaw, err := json.Marshal(scope)
	if err != nil {
		return fence, err
	}
	receiptPath, err := g.receiptPath(s.productID)
	if err != nil {
		return fence, err
	}
	fence = TerminalFence{Version: 1, InstallationID: s.productID, Incarnation: s.incarnation, TransactionID: txnID, ApprovalDigest: probe.ApprovalDigest, ScopeDigest: provision.DomainDigest("chatanium-terminal-scope-v1", scopeRaw), ReceiptPath: receiptPath, SourceControl: s.sourceControl, SourceDatabase: s.sourceDatabase, ApprovedPlan: append([]byte(nil), approvalRaw...), Remaining: append([]TerminalObject(nil), remaining...), AbsenceGuards: append([]TerminalGuard(nil), guards...)}
	fence.SourceControl, err = terminalObserve(s.dir, false)
	if err != nil {
		return fence, err
	}
	fence.Cleanup = e
	fence.FrozenManifest, err = terminalObserve(filepath.Join(s.dir, "installation.json"), true)
	if err != nil {
		return fence, err
	}
	if fence.FrozenManifest.Absent {
		return fence, errors.New("terminal source has no original installation witness")
	}
	s.manifestMu.Lock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.manifestMu.Unlock()
		return fence, err
	}
	defer tx.Rollback()
	m.State = "TERMINAL_PURGE"
	m.ManifestGeneration++
	m.Terminal = &TerminalWitness{Version: 1, InstallationID: fence.InstallationID, Incarnation: fence.Incarnation, TransactionID: fence.TransactionID, ApprovalDigest: fence.ApprovalDigest, ScopeDigest: fence.ScopeDigest, ReceiptPath: fence.ReceiptPath}
	manifestRaw, err := json.Marshal(m)
	if err == nil {
		_, err = tx.ExecContext(ctx, "UPDATE runtime_installations SET manifest=? WHERE id=?", manifestRaw, s.productID)
	}
	if err == nil {
		var raw []byte
		raw, err = json.Marshal(fence)
		if err == nil {
			_, err = tx.ExecContext(ctx, "INSERT INTO metadata VALUES('terminal_fence',?)", raw)
		}
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, "INSERT INTO metadata VALUES('mirror_pending',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", strconv.FormatUint(m.ManifestGeneration, 10))
	}
	if err == nil {
		err = tx.Commit()
	}
	s.manifestMu.Unlock()
	if err != nil {
		return fence, err
	}
	s.terminalOnly = true
	return s.finishTerminalFreeze(ctx, g, fence)
}

type terminalMirrorPublication struct {
	Native  TerminalNativeIdentity `json:"native"`
	Payload []byte                 `json:"payload"`
}

func (s *Store) finishTerminalFreeze(ctx context.Context, g *ManagementGuard, fence TerminalFence) (TerminalFence, error) {
	return s.finishTerminalFreezeWithSync(ctx, g, fence, (*os.File).Sync)
}
func (s *Store) finishTerminalFreezeWithSync(ctx context.Context, g *ManagementGuard, fence TerminalFence, syncControl func(*os.File) error) (TerminalFence, error) {
	if syncControl == nil {
		return fence, errors.New("terminal frozen witness requires explicit directory durability barrier")
	}
	if err := s.terminalAuthority(g); err != nil {
		return fence, err
	}
	if fence.Frozen {
		if err := VerifyTerminalPurgeSource(ctx, g, TerminalPurgeSeal{Version: 1, InstallationID: fence.InstallationID, Incarnation: fence.Incarnation, TransactionID: fence.TransactionID, ApprovalDigest: fence.ApprovalDigest, ApprovedPlan: fence.ApprovedPlan, ReceiptPath: fence.ReceiptPath, SourceControl: fence.SourceControl, SourceDatabase: fence.SourceDatabase, FrozenManifest: fence.FrozenManifest}); err != nil {
			return fence, err
		}
		return fence, nil
	}
	m, err := s.Installation(ctx)
	if err != nil {
		return fence, err
	}
	if m.State != "TERMINAL_PURGE" || m.Terminal == nil || m.Terminal.Incarnation != fence.Incarnation || m.Terminal.TransactionID != fence.TransactionID || m.Terminal.ApprovalDigest != fence.ApprovalDigest {
		return fence, errors.New("terminal frozen witness source binding changed")
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return fence, err
	}
	canonical := filepath.Join(s.dir, "installation.json")
	next := filepath.Join(s.dir, "installation.json.next")
	var publication terminalMirrorPublication
	publicationErr := terminalReadRecord(ctx, s, "terminal_mirror", &publication)
	if publicationErr != nil && !errors.Is(publicationErr, sql.ErrNoRows) {
		return fence, publicationErr
	}
	if publicationErr == nil && !bytes.Equal(publication.Payload, payload) {
		return fence, errors.New("terminal frozen manifest exact bytes changed")
	}
	current, err := terminalObserve(canonical, true)
	if err != nil {
		return fence, err
	}
	published := false
	if publicationErr == nil {
		expected := publication.Native
		expected.Path = canonical
		published = terminalIdentityMatches(expected, current, false)
	}
	directoryFD, err := unix.Open(s.dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fence, err
	}
	directory := os.NewFile(uintptr(directoryFD), "terminal-source-control")
	defer directory.Close()
	if !published {
		if !terminalIdentityMatches(fence.FrozenManifest, current, false) {
			return fence, errors.New("terminal original witness was replaced before frozen publication")
		}
		nextNative, err := terminalObserve(next, true)
		if err != nil {
			return fence, err
		}
		knownNext := false
		if publicationErr == nil {
			knownNext = terminalIdentityMatches(publication.Native, nextNative, false)
		}
		if !nextNative.Absent && !knownNext {
			owned := false
			for _, target := range fence.Remaining {
				if target.Native.Path == next {
					owned = terminalIdentityMatches(target.Native, nextNative, false)
				}
			}
			if !owned {
				return fence, errors.New("unrecognized terminal manifest staging inode")
			}
			if err = unix.Unlinkat(directoryFD, "installation.json.next", 0); err != nil {
				return fence, err
			}
			if err = directory.Sync(); err != nil {
				return fence, err
			}
			nextNative = TerminalNativeIdentity{Path: next, Absent: true}
		}
		if nextNative.Absent {
			fd, err := unix.Openat(directoryFD, ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0600)
			if err != nil {
				return fence, err
			}
			file := os.NewFile(uintptr(fd), "anonymous-frozen-installation-witness")
			defer file.Close()
			if _, err = file.Write(payload); err != nil {
				return fence, err
			}
			if err = file.Sync(); err != nil {
				return fence, err
			}
			native, err := terminalAnonymous(file, payload, next, g.uid)
			if err != nil {
				return fence, err
			}
			native.Links = 1
			publication = terminalMirrorPublication{Native: native, Payload: payload}
			if err = terminalWriteRecord(ctx, s, "terminal_mirror", publication); err != nil {
				return fence, err
			}
			if err = LinkAnonymous(file, directoryFD, "installation.json.next"); err != nil {
				return fence, err
			}
			if err = directory.Sync(); err != nil {
				return fence, err
			}
		}
		if err = unix.Renameat(directoryFD, "installation.json.next", directoryFD, "installation.json"); err != nil {
			return fence, err
		}
		if err = directory.Sync(); err != nil {
			return fence, err
		}
	}
	fence.FrozenManifest, err = terminalObserve(canonical, true)
	if err != nil {
		return fence, err
	}
	expected := publication.Native
	expected.Path = canonical
	if !terminalIdentityMatches(expected, fence.FrozenManifest, false) {
		return fence, errors.New("terminal frozen witness publication proof failed")
	}
	if err = syncControl(directory); err != nil {
		return fence, err
	}
	fence.Frozen = true
	for index := range fence.Remaining {
		path := fence.Remaining[index].Native.Path
		if path == canonical {
			fence.Remaining[index].Native = fence.FrozenManifest
		}
		if path == next {
			fence.Remaining[index].Native = TerminalNativeIdentity{Path: next, Absent: true}
		}
	}
	if err = terminalWriteRecord(ctx, s, "terminal_fence", fence); err != nil {
		return fence, err
	}
	if _, err = s.db.ExecContext(ctx, "DELETE FROM metadata WHERE key='mirror_pending'"); err != nil {
		return fence, err
	}
	return fence, nil
}

func VerifyTerminalPurgeSource(ctx context.Context, g *ManagementGuard, seal TerminalPurgeSeal) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := g.require(false); err != nil {
		return err
	}
	if seal.Version != 1 || !safeID(seal.InstallationID) || !safeID(seal.Incarnation) || !terminalKeyID(seal.TransactionID) {
		return invalid("terminal source identity is invalid")
	}
	planID, digest, scope, err := terminalApproval(seal.ApprovedPlan, seal.InstallationID)
	if err != nil {
		return err
	}
	if planID != seal.TransactionID || digest != seal.ApprovalDigest {
		return errors.New("terminal source approval binding differs")
	}
	receiptPath, err := g.receiptPath(seal.InstallationID)
	if err != nil {
		return err
	}
	if seal.ReceiptPath != receiptPath || seal.SourceDatabase.Path != filepath.Join(seal.SourceControl.Path, "supervisor.sqlite") || seal.FrozenManifest.Path != filepath.Join(seal.SourceControl.Path, "installation.json") || seal.SourceDatabase.Digest != "" {
		return invalid("terminal source paths or mutable database binding differ")
	}
	actualDB, err := terminalObserve(seal.SourceDatabase.Path, false)
	if err != nil {
		return err
	}
	actualControl, err := terminalObserve(seal.SourceControl.Path, false)
	if err != nil {
		return err
	}
	if !terminalIdentityMatches(seal.SourceDatabase, actualDB, true) || !terminalIdentityMatches(seal.SourceControl, actualControl, true) {
		return errors.New("terminal source belongs to a different native incarnation")
	}
	witness, err := terminalObserve(seal.FrozenManifest.Path, true)
	if err != nil {
		return err
	}
	if !actualDB.Absent && (actualControl.Absent || witness.Absent) {
		return errors.New("coexisting source database lacks frozen terminal witness")
	}
	if witness.Absent {
		return nil
	}
	if !terminalIdentityMatches(seal.FrozenManifest, witness, false) {
		return errors.New("terminal frozen witness changed or belongs to another incarnation")
	}
	fd, err := unix.Open(witness.Path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "verified-terminal-frozen-witness")
	raw, err := io.ReadAll(io.LimitReader(file, durableJSONMax+1))
	file.Close()
	if err != nil {
		return err
	}
	var manifest InstallationManifest
	if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &manifest); err != nil {
		return err
	}
	scopeRaw, err := json.Marshal(scope)
	if err != nil {
		return err
	}
	want := TerminalWitness{Version: 1, InstallationID: seal.InstallationID, Incarnation: seal.Incarnation, TransactionID: seal.TransactionID, ApprovalDigest: seal.ApprovalDigest, ScopeDigest: provision.DomainDigest("chatanium-terminal-scope-v1", scopeRaw), ReceiptPath: seal.ReceiptPath}
	if manifest.State != "TERMINAL_PURGE" || manifest.RuntimeInstallationID != seal.InstallationID || manifest.Paths.Control != seal.SourceControl.Path || manifest.Terminal == nil || *manifest.Terminal != want {
		return errors.New("terminal source witness is not the sealed approval and transaction")
	}
	return nil
}
func (s *Store) BindTerminalPurgePublication(ctx context.Context, g *ManagementGuard, seal TerminalPurgeSeal, anonymous *os.File, initialReceipt []byte, expectedAttempt uint64) (TerminalPublicationBinding, error) {
	var binding TerminalPublicationBinding
	if err := s.terminalAuthority(g); err != nil {
		return binding, err
	}
	fence, err := s.TerminalPurgeFence(ctx)
	if err != nil {
		return binding, err
	}
	if !fence.Frozen {
		return binding, errors.New("terminal source witness publication is incomplete")
	}
	if seal.Version != 1 || seal.InstallationID != fence.InstallationID || seal.Incarnation != fence.Incarnation || seal.TransactionID != fence.TransactionID || seal.ApprovalDigest != fence.ApprovalDigest || !bytes.Equal(seal.ApprovedPlan, fence.ApprovedPlan) || seal.ReceiptPath != fence.ReceiptPath || seal.SourceControl != fence.SourceControl || seal.SourceDatabase != fence.SourceDatabase || seal.FrozenManifest != fence.FrozenManifest || !terminalSameJSON(seal.Remaining, fence.Remaining) || !terminalSameJSON(seal.AbsenceGuards, fence.AbsenceGuards) {
		return binding, errors.New("terminal receipt cannot grow or replace frozen source authority")
	}
	if err = VerifyTerminalPurgeSource(ctx, g, seal); err != nil {
		return binding, err
	}
	native, err := terminalAnonymous(anonymous, initialReceipt, seal.ReceiptPath, g.uid)
	if err != nil {
		return binding, err
	}
	rootFD, err := g.RootFD()
	if err != nil {
		return binding, err
	}
	var root unix.Stat_t
	if err = unix.Fstat(rootFD, &root); err != nil {
		return binding, err
	}
	if native.Device != uint64(root.Dev) {
		return binding, errors.New("terminal receipt anonymous inode is on a different filesystem")
	}
	native.Links = 1
	if expectedAttempt == ^uint64(0) {
		return binding, errors.New("terminal publication attempts exhausted")
	}
	sealRaw, err := json.Marshal(seal)
	if err != nil {
		return binding, err
	}
	binding = TerminalPublicationBinding{Attempt: expectedAttempt + 1, Seal: seal, SealDigest: provision.DomainDigest("chatanium-terminal-seal-v1", sealRaw), Payload: append([]byte(nil), initialReceipt...), PayloadDigest: provision.Digest(initialReceipt), Native: native}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return binding, err
	}
	defer tx.Rollback()
	var raw []byte
	err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='terminal_publication'").Scan(&raw)
	if err == nil {
		var old TerminalPublicationBinding
		if err = gvxcontract.DecodeStrict(raw, terminalJSONMax, 48, &old); err != nil {
			return binding, err
		}
		if old.Attempt != expectedAttempt || old.SealDigest != binding.SealDigest || !terminalSameJSON(old.Seal, seal) {
			return binding, errors.New("terminal prelink publication compare-and-swap mismatch")
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		if expectedAttempt != 0 {
			return binding, errors.New("terminal publication expected attempt is absent")
		}
	} else {
		return binding, err
	}
	raw, err = json.Marshal(binding)
	if err != nil {
		return binding, err
	}
	if len(raw) > terminalJSONMax {
		return binding, invalid("terminal publication source binding exceeds bound")
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO metadata VALUES('terminal_publication',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", raw); err != nil {
		return binding, err
	}
	if err = tx.Commit(); err != nil {
		return binding, err
	}
	return binding, nil
}
func OpenTerminalPurgeSource(ctx context.Context, dir, id string, g *ManagementGuard) (*Store, error) {
	if err := g.require(true); err != nil {
		return nil, err
	}
	if err := g.checkNoReceipt(id); err != nil {
		return nil, err
	}
	if !safeID(id) || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, invalid("invalid terminal source locator")
	}
	control, err := terminalObserve(dir, false)
	if err != nil {
		return nil, err
	}
	if control.Absent {
		return nil, os.ErrNotExist
	}
	if control.Kind != "directory" || control.UID != g.uid || control.Mode&0022 != 0 {
		return nil, errors.New("terminal source control is not protected")
	}
	database, err := terminalObserve(filepath.Join(dir, "supervisor.sqlite"), false)
	if err != nil {
		return nil, err
	}
	if database.Absent {
		return nil, os.ErrNotExist
	}
	store, err := openStoreDBMode(ctx, dir, false, g, true)
	if err != nil {
		return nil, err
	}
	store.productID = id
	if err = store.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='incarnation'").Scan(&store.incarnation); err != nil {
		store.Close()
		return nil, err
	}
	if err = store.validateTerminalPurgeMetadata(ctx); err != nil {
		store.Close()
		return nil, err
	}
	return store, nil
}

func validateTerminalAccountGuard(guard TerminalGuard) error {
	if guard.Name == "" || len(guard.Name) > 31 || guard.GID == 0 || guard.GroupOnly && guard.UID != 0 || !guard.GroupOnly && guard.UID == 0 {
		return invalid("terminal account guard is not a representable owned account or group")
	}
	for index, c := range guard.Name {
		if !(c >= 'a' && c <= 'z' || c == '_' || index > 0 && (c >= '0' && c <= '9' || c == '-')) {
			return invalid("terminal account guard name differs from supported account-name grammar")
		}
	}
	return nil
}

func (s *Store) validateTerminalPurgeMetadata(ctx context.Context) error {
	if !safeID(s.incarnation) || s.sourceControl.Absent || s.sourceControl.Kind != "directory" || s.sourceControl.UID != s.gate.uid || s.sourceControl.Mode&0022 != 0 || s.sourceDatabase.Absent || s.sourceDatabase.Kind != "file" || s.sourceDatabase.UID != s.gate.uid || s.sourceDatabase.Mode != 0600 || s.sourceDatabase.Links != 1 {
		return errors.New("passive terminal source native incarnation is unsafe")
	}
	manifest, err := s.Installation(ctx)
	if err != nil {
		return err
	}
	if manifest.Paths.Control != s.dir {
		return errors.New("terminal source manifest locator changed")
	}
	fence, fenceErr := s.TerminalPurgeFence(ctx)
	if fenceErr == nil {
		planID, digest, scope, err := terminalApproval(fence.ApprovedPlan, s.productID)
		if err != nil {
			return err
		}
		receipt, err := s.gate.receiptPath(s.productID)
		if err != nil {
			return err
		}
		scopeRaw, err := json.Marshal(scope)
		if err != nil {
			return err
		}
		want := TerminalWitness{Version: 1, InstallationID: s.productID, Incarnation: s.incarnation, TransactionID: planID, ApprovalDigest: digest, ScopeDigest: provision.DomainDigest("chatanium-terminal-scope-v1", scopeRaw), ReceiptPath: receipt}
		if fence.Version != 1 || fence.InstallationID != s.productID || fence.Incarnation != s.incarnation || fence.TransactionID != planID || fence.ApprovalDigest != digest || fence.ScopeDigest != want.ScopeDigest || fence.ReceiptPath != receipt || fence.SourceControl.Path != s.dir || fence.SourceDatabase.Path != filepath.Join(s.dir, "supervisor.sqlite") || fence.SourceControl.Device != s.sourceControl.Device || fence.SourceControl.Inode != s.sourceControl.Inode || fence.SourceDatabase.Device != s.sourceDatabase.Device || fence.SourceDatabase.Inode != s.sourceDatabase.Inode || manifest.State != "TERMINAL_PURGE" || manifest.Terminal == nil || *manifest.Terminal != want {
			return errors.New("terminal source fence, original approval or native incarnation changed")
		}
		if fence.Frozen {
			seal := TerminalPurgeSeal{Version: 1, InstallationID: fence.InstallationID, Incarnation: fence.Incarnation, TransactionID: fence.TransactionID, ApprovalDigest: fence.ApprovalDigest, ApprovedPlan: fence.ApprovedPlan, ReceiptPath: fence.ReceiptPath, SourceControl: fence.SourceControl, SourceDatabase: fence.SourceDatabase, FrozenManifest: fence.FrozenManifest}
			if err = VerifyTerminalPurgeSource(ctx, s.gate, seal); err != nil {
				return err
			}
		}
		s.terminalOnly = true
	} else {
		if !errors.Is(fenceErr, sql.ErrNoRows) {
			return fenceErr
		}
		probe, err := s.ActiveTerminalPublicationProbe(ctx)
		if err != nil {
			return err
		}
		planID, digest, _, err := terminalApproval(probe.ApprovedPlan, s.productID)
		if err != nil {
			return err
		}
		if probe.Version != 1 || probe.InstallationID != s.productID || probe.Incarnation != s.incarnation || probe.TransactionID != planID || probe.ApprovalDigest != digest || probe.Attempt == 0 {
			return errors.New("terminal probe source approval or incarnation changed")
		}
		for index, path := range probe.Paths {
			expected, err := s.gate.stagePath(s.productID, planID, uint64(index))
			if err != nil {
				return err
			}
			if path != expected {
				return errors.New("terminal probe source slot changed")
			}
		}
		s.terminalOnly = false
	}
	control, err := terminalObserve(s.dir, false)
	if err != nil {
		return err
	}
	database, err := terminalObserve(filepath.Join(s.dir, "supervisor.sqlite"), false)
	if err != nil {
		return err
	}
	if !terminalIdentityMatches(s.sourceControl, control, false) || !terminalIdentityMatches(s.sourceDatabase, database, false) {
		return errors.New("terminal source native identity changed during metadata read")
	}
	return nil
}
func validateTerminalAccountGuardSource(guard TerminalGuard, properties ProvisionProperties) error {
	if properties.Source != "" && properties.Source != "group" || guard.Name != properties.Name || guard.UID != properties.UID || guard.GID != properties.GID || guard.GroupOnly != (properties.Source == "group") {
		return errors.New("terminal account guard changed original numeric identity or disposition")
	}
	return validateTerminalAccountGuard(guard)
}
