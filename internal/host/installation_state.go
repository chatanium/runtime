//go:build linux

package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/thirdscam/chatanium/internal/provision"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"golang.org/x/sys/unix"
)

const durableJSONMax = 4 << 20
const revisionConfigMax = 16 << 20
const revisionJSONMax = 64 << 20

type InstallationLease struct {
	store  *Store
	file   *os.File
	owner  UnitIdentity
	mu     sync.Mutex
	closed bool
}

func CreateStore(ctx context.Context, m InstallationManifest, g *ManagementGuard) (*Store, error) {
	return createStore(ctx, m, nil, g)
}
func CreateStoreWithManagementPlan(ctx context.Context, m InstallationManifest, plan ManagementPlanRecord, g *ManagementGuard) (*Store, error) {
	if plan.Kind != "init" || plan.Phase != "APPROVED" || plan.Step != 0 {
		return nil, invalid("initial management journal requires approved init plan")
	}
	if err := validateManagementPlan(plan, m.RuntimeInstallationID); err != nil {
		return nil, err
	}
	return createStore(ctx, m, &plan, g)
}
func createStore(ctx context.Context, m InstallationManifest, plan *ManagementPlanRecord, g *ManagementGuard) (*Store, error) {
	if err := g.require(false); err != nil {
		return nil, err
	}
	if err := g.checkNoReceipt(m.RuntimeInstallationID); err != nil {
		return nil, err
	}
	if m.Format != gvxcontract.InstallationFormat || m.FormatVersion != 1 || m.SchemaVersion != 1 || !safeID(m.RuntimeInstallationID) || m.State != "PROVISIONING" || m.DesiredRunState != "STOPPED" || !filepath.IsAbs(m.Paths.Control) {
		return nil, invalid("invalid initial installation manifest")
	}
	if m.Budget.AppBytes <= 0 || m.Budget.AppInodes <= 0 || m.Budget.AppBytes > m.Budget.DataBytes || m.Budget.AppInodes > m.Budget.DataInodes {
		return nil, invalid("finite native app allowance must fit existing data pool")
	}
	d, anchors, err := createControlAnchor(m.Paths.Control, m.Identities.App.GID)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	fd, err := unix.Openat(int(d.Fd()), "supervisor.sqlite", unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	unix.Close(fd)
	s, err := openStoreDB(ctx, m.Paths.Control, true, g)
	if err != nil {
		return nil, err
	}
	s.productID = m.RuntimeInstallationID
	m.ManifestGeneration = 1
	raw, err := json.Marshal(m)
	if err != nil {
		s.Close()
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.Close()
		return nil, err
	}
	defer tx.Rollback()
	if err = initializeSchemaTx(ctx, tx); err != nil {
		tx.Rollback()
		s.Close()
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO runtime_installations VALUES(?,?)", s.productID, raw); err != nil {
		s.Close()
		return nil, err
	}
	for _, attrs := range anchors {
		encoded, e := json.Marshal(attrs)
		if e != nil {
			err = e
			break
		}
		entry := ProvisionRecord{ProvisionIntent: ProvisionIntent{ID: newID(), Kind: "directory", Identity: attrs.Path, ProductCreated: true, Desired: encoded}, Observed: ObjectObservation{Identity: attrs.Path, Attributes: encoded}, State: "OBSERVED", CleanupState: "PENDING"}
		ledger, e := json.Marshal(entry)
		if e != nil {
			err = e
			break
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO provisioning_ledger VALUES(?,?,?,?)", entry.ID, entry.Kind, entry.Identity, ledger); err != nil {
			break
		}
	}
	if err == nil {
		err = recordManagementAnchorTx(ctx, tx, g, plan)
	}
	if err == nil && plan != nil {
		err = beginManagementPlanTx(ctx, tx, s.productID, *plan)
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, "INSERT INTO metadata VALUES('mirror_pending','1')")
	}
	if err == nil {
		err = tx.Commit()
	} else {
		tx.Rollback()
	}
	if err == nil {
		err = s.publishMirror(m)
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
func OpenStore(ctx context.Context, dir, id string, g *ManagementGuard) (*Store, error) {
	if err := g.require(false); err != nil {
		return nil, err
	}
	if err := g.checkNoReceipt(id); err != nil {
		return nil, err
	}
	if !safeID(id) {
		return nil, invalid("invalid product installation ID")
	}
	d, err := trustedDirectory(dir)
	if err != nil {
		return nil, err
	}
	d.Close()
	s, err := openStoreDB(ctx, dir, false, g)
	if err != nil {
		return nil, err
	}
	s.productID = id
	m, err := s.Installation(ctx)
	if err != nil {
		s.Close()
		return nil, err
	}
	if m.Paths.Control != dir {
		s.Close()
		return nil, errors.New("installation control locator mismatch")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "installation.json"))
	needsMirror := false
	if err == nil {
		var mirror InstallationManifest
		err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &mirror)
		if err == nil && (mirror.RuntimeInstallationID != id || mirror.Format != m.Format || mirror.FormatVersion != m.FormatVersion || mirror.SchemaVersion != m.SchemaVersion || mirror.ManifestGeneration > m.ManifestGeneration) {
			err = errors.New("installation mirror identity/version/generation mismatch")
		}
		if err == nil && mirror.ManifestGeneration == m.ManifestGeneration {
			exact, _ := json.Marshal(m)
			if string(exact) != string(raw) {
				err = errors.New("installation mirror differs from authoritative generation")
			}
		}
		needsMirror = err == nil && mirror.ManifestGeneration < m.ManifestGeneration
	} else if errors.Is(err, os.ErrNotExist) {
		err = nil
		needsMirror = true
	}
	if err == nil && needsMirror {
		var pending string
		if e := s.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='mirror_pending'").Scan(&pending); e != nil || pending != strconv.FormatUint(m.ManifestGeneration, 10) {
			err = errors.New("missing mirror lacks matching durable publication intent")
		}
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.installationLease != nil {
		return errors.New("installation lease is still held")
	}
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.db.Close()
	if s.gateOwned && s.gate != nil {
		err = errors.Join(err, s.gate.Close())
	}
	return err
}
func (s *Store) AcquireLease(ctx context.Context) (*InstallationLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.gate == nil {
		return nil, ErrManagementGuardRequired
	}
	if err := s.gate.require(s.terminalOnly); err != nil {
		return nil, err
	}
	if err := s.checkSourceAdmission(ctx, s.terminalOnly); err != nil {
		return nil, err
	}
	if s.installationLease != nil {
		return nil, errors.New("installation lease already held")
	}
	fd, err := unix.Open(filepath.Join(s.dir, "installation.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "installation-lease")
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	l := &InstallationLease{store: s, file: f}
	s.installationLease = l
	if err := s.checkSourceAdmission(ctx, s.terminalOnly); err != nil {
		s.installationLease = nil
		f.Close()
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='incarnation'").Scan(&s.incarnation); err != nil {
		s.installationLease = nil
		f.Close()
		return nil, err
	}
	if s.terminalOnly {
		return l, nil
	}
	var pending string
	err = s.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='mirror_pending'").Scan(&pending)
	if err == nil {
		m, e := s.Installation(ctx)
		if e == nil && pending != strconv.FormatUint(m.ManifestGeneration, 10) {
			e = errors.New("mirror publication intent generation mismatch")
		}
		if e == nil {
			e = s.publishMirror(m)
		}
		if e != nil {
			s.installationLease = nil
			f.Close()
			return nil, e
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		s.installationLease = nil
		f.Close()
		return nil, err
	}
	if s.gateOwned {
		if err := s.gate.Close(); err != nil {
			s.installationLease = nil
			f.Close()
			return nil, err
		}
		s.gateOwned = false
	}
	return l, nil
}
func (l *InstallationLease) BindOwner(ctx context.Context, u UnitIdentity) error {
	if err := l.store.requireLease(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || !validUnit(u) || u.MainPID != os.Getpid() {
		return errors.New("invalid installation owner binding")
	}
	if l.owner.Name != "" && l.owner != u {
		return errors.New("installation owner already bound")
	}
	raw, err := json.Marshal(u)
	if err != nil {
		return err
	}
	_, err = l.store.db.ExecContext(ctx, "INSERT INTO metadata(key,value) VALUES('lease_owner',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", string(raw))
	if err == nil {
		l.owner = u
	}
	return err
}
func (l *InstallationLease) Close() error {
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	var closeErr error
	if l.store.gate == nil || l.store.gate.Mode() != ManagementExclusive {
		closeErr = l.store.db.Close()
		l.store.closed = true
	}
	l.closed = true
	l.store.installationLease = nil
	return errors.Join(closeErr, l.file.Close())
}
func (s *Store) Installation(ctx context.Context) (InstallationManifest, error) {
	var m InstallationManifest
	var raw []byte
	if err := s.db.QueryRowContext(ctx, "SELECT manifest FROM runtime_installations WHERE id=?", s.productID).Scan(&raw); err != nil {
		return m, err
	}
	if err := gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &m); err != nil {
		return m, err
	}
	if m.Format != gvxcontract.InstallationFormat || m.FormatVersion != 1 || m.SchemaVersion != 1 || m.RuntimeInstallationID != s.productID {
		return m, errors.New("unsupported installation format")
	}
	return m, nil
}
func (s *Store) requireLease() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.installationLease == nil || s.installationLease.closed {
		return errors.New("installation lease required")
	}
	if s.terminalOnly {
		return ErrTerminalPurge
	}
	return s.checkSourceAdmission(context.Background(), false)
}
func (s *Store) publishMirror(m InstallationManifest) error {
	if err := s.checkSourceAdmission(context.Background(), false); err != nil {
		return err
	}
	return s.publishMirrorUnchecked(m)
}
func (s *Store) publishMirrorUnchecked(m InstallationManifest) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, "installation.json.next")
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if errors.Is(err, unix.EEXIST) {
		prior, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		var pending InstallationManifest
		if e = gvxcontract.DecodeStrict(prior, durableJSONMax, 32, &pending); e != nil || pending.RuntimeInstallationID != m.RuntimeInstallationID || pending.ManifestGeneration > m.ManifestGeneration {
			return errors.New("unproven interrupted installation publication")
		}
		if e = os.Remove(path); e != nil {
			return e
		}
		fd, err = unix.Open(path, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "installation-mirror")
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(path, filepath.Join(s.dir, "installation.json")); err != nil {
		return err
	}
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	err = errors.Join(d.Sync(), d.Close())
	if err != nil {
		return err
	}
	_, err = s.db.Exec("DELETE FROM metadata WHERE key='mirror_pending' AND value=?", strconv.FormatUint(m.ManifestGeneration, 10))
	return err
}
func (s *Store) updateInstallation(ctx context.Context, change func(*InstallationManifest, *sql.Tx) error) error {
	s.manifestMu.Lock()
	defer s.manifestMu.Unlock()
	if err := s.requireLease(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw []byte
	if err = tx.QueryRowContext(ctx, "SELECT manifest FROM runtime_installations WHERE id=?", s.productID).Scan(&raw); err != nil {
		return err
	}
	var m InstallationManifest
	if err = gvxcontract.DecodeStrict(raw, durableJSONMax, 32, &m); err != nil {
		return err
	}
	if err = change(&m, tx); err != nil {
		return err
	}
	if m.ManifestGeneration == ^uint64(0) {
		return errors.New("installation manifest generation exhausted")
	}
	m.ManifestGeneration++
	raw, err = json.Marshal(m)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE runtime_installations SET manifest=? WHERE id=?", raw, s.productID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO metadata VALUES('mirror_pending',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", strconv.FormatUint(m.ManifestGeneration, 10)); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return s.publishMirror(m)
}
func (s *Store) SetDesired(ctx context.Context, state, intent string) error {
	if (state != "RUNNING" && state != "STOPPED") || !safeID(intent) {
		return invalid("invalid desired state or intent")
	}
	return s.updateInstallation(ctx, func(m *InstallationManifest, tx *sql.Tx) error {
		if state == "RUNNING" && (m.State != "READY" || m.ActiveRevision == "" || m.PendingRevision != "") {
			return errors.New("RUNNING requires active READY release without pending replacement")
		}
		if state == "RUNNING" {
			var active int
			if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM metadata WHERE key IN ('management_active','terminal_probe_active','terminal_fence')").Scan(&active); err != nil {
				return err
			}
			if active != 0 {
				return errors.New("approved management transaction must be completed before RUNNING")
			}
			var raw []byte
			if err := tx.QueryRowContext(ctx, "SELECT record FROM revisions WHERE id=?", m.ActiveRevision).Scan(&raw); err != nil {
				return err
			}
			var revision RevisionRecord
			if err := gvxcontract.DecodeStrict(raw, revisionJSONMax, 32, &revision); err != nil {
				return err
			}
			if err := checkRevisionUsableTx(ctx, tx, revision); err != nil {
				return err
			}
		}
		m.DesiredRunState = state
		m.DesiredIntentID = intent
		return nil
	})
}
func (s *Store) SetPendingRevision(ctx context.Context, r RevisionRecord) error {
	if r.DevelopmentWorker != nil {
		return errors.New("development revision cannot become a release candidate")
	}
	if !validLedgerID(r.ID) || r.ConfigDigest != provision.Digest(r.Config) || r.BundleDigest == "" || len(r.Config) == 0 {
		return invalid("invalid immutable revision")
	}
	var config any
	if err := gvxcontract.DecodeStrict(r.Config, revisionConfigMax, 32, &config); err != nil {
		return err
	}
	if err := validateRevisionLaunchPolicies(r); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(raw) > revisionJSONMax {
		return errors.New("revision exceeds durable metadata bound")
	}
	return s.updateInstallation(ctx, func(m *InstallationManifest, tx *sql.Tx) error {
		if m.DesiredRunState != "STOPPED" {
			return errors.New("revision replacement requires STOPPED")
		}
		if err := bindInitializationPendingTx(ctx, tx, s.productID, *m, r); err != nil {
			return err
		}
		var previous []byte
		e := tx.QueryRowContext(ctx, "SELECT record FROM revisions WHERE id=?", r.ID).Scan(&previous)
		if e == nil && string(previous) != string(raw) {
			return errors.New("revision identity reuse")
		}
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO revisions VALUES(?,?)", r.ID, raw); e != nil {
			return e
		}
		if e = checkRevisionUsableTx(ctx, tx, r); e != nil {
			return e
		}
		if e = retainRevisionTx(ctx, tx, r); e != nil {
			return e
		}
		m.PendingRevision = r.ID
		return nil
	})
}
func validateCleanup(e CleanupEvidence) error { return validateScopedCleanup(e, true, true) }
func validateScopedCleanup(e CleanupEvidence, mounts, quota bool) error {
	if e.BootID == "" || !e.JobsAbsent || !e.ProcessesAbsent || !e.TransportsClosed || !e.OpenReferencesAbsent || mounts && !e.MountsAbsent || quota && !e.QuotaReclaimed || len(e.Details) > durableJSONMax {
		return ErrCleanupIncomplete
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(boot)) != e.BootID {
		return errors.New("cleanup evidence belongs to another boot")
	}
	return nil
}
func (s *Store) ActivateRevision(ctx context.Context, id string, e CleanupEvidence) error {
	if err := validateCleanup(e); err != nil {
		return err
	}
	return s.updateInstallation(ctx, func(m *InstallationManifest, tx *sql.Tx) error {
		if m.PendingRevision != id || id == "" || m.DesiredRunState != "STOPPED" {
			return errors.New("pending release revision/state mismatch")
		}
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM instances WHERE cleanup!='COMPLETE'").Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			return ErrCleanupIncomplete
		}
		var raw []byte
		if err := tx.QueryRowContext(ctx, "SELECT record FROM revisions WHERE id=?", id).Scan(&raw); err != nil {
			return err
		}
		var r RevisionRecord
		if err := gvxcontract.DecodeStrict(raw, revisionJSONMax, 32, &r); err != nil {
			return err
		}
		if r.DevelopmentWorker != nil {
			return errors.New("development revision cannot be activated as release")
		}
		if err := validateRevisionLaunchPolicies(r); err != nil {
			return err
		}
		if err := checkRevisionUsableTx(ctx, tx, r); err != nil {
			return err
		}
		if err := retainRevisionTx(ctx, tx, r); err != nil {
			return err
		}
		m.ActiveRevision = id
		m.PendingRevision = ""
		m.BundleDigest = r.BundleDigest
		m.State = "READY"
		return nil
	})
}
func (s *Store) RequireRecovery(ctx context.Context, reason string) error {
	if reason == "" || len(reason) > 256 {
		return invalid("invalid recovery reason")
	}
	return s.updateInstallation(ctx, func(m *InstallationManifest, tx *sql.Tx) error {
		m.State = "RECOVERY_REQUIRED"
		_, err := tx.ExecContext(ctx, "INSERT INTO metadata VALUES('recovery_reason',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", reason)
		return err
	})
}
func bootTimeNS() (int64, error) {
	var t unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &t)
	return t.Nano(), err
}

func (s *Store) Revision(ctx context.Context, id string) (RevisionRecord, error) {
	var r RevisionRecord
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT record FROM revisions WHERE id=?", id).Scan(&raw)
	if err == nil {
		err = gvxcontract.DecodeStrict(raw, revisionJSONMax, 32, &r)
	}
	return r, err
}
func (s *Store) SetBacking(ctx context.Context, b BackingIdentity) error {
	if b.Dev == 0 || b.Ino == 0 || b.XFSUUID == "" || b.SizeBytes <= 0 {
		return errors.New("incomplete observed backing identity")
	}
	return s.updateInstallation(ctx, func(m *InstallationManifest, tx *sql.Tx) error {
		if m.State != "PROVISIONING" || m.Backing.Dev != 0 && m.Backing != b {
			return errors.New("known backing identity cannot be reformatted/replaced")
		}
		rows, err := tx.QueryContext(ctx, "SELECT record FROM provisioning_ledger WHERE kind='backing' AND identity=?", m.Paths.BackingFile)
		if err != nil {
			return err
		}
		found := false
		for rows.Next() {
			var raw []byte
			if err = rows.Scan(&raw); err != nil {
				rows.Close()
				return err
			}
			var r ProvisionRecord
			if err = decodeProvisionRecord(raw, &r); err != nil {
				rows.Close()
				return err
			}
			if r.State != "OBSERVED" {
				continue
			}
			var p ProvisionProperties
			if err = gvxcontract.DecodeStrict(r.Observed.Attributes, 64<<10, 8, &p); err != nil {
				rows.Close()
				return err
			}
			if p.Dev == b.Dev && p.Ino == b.Ino && p.UUID == b.XFSUUID && p.SizeBytes == b.SizeBytes {
				found = true
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if !found {
			return errors.New("backing identity lacks observed provisioning intent")
		}
		m.Backing = b
		return nil
	})
}

func (s *Store) AssertRemovable(ctx context.Context) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	m, err := s.Installation(ctx)
	if err != nil {
		return err
	}
	if m.DesiredRunState != "STOPPED" {
		return errors.New("installation still desires RUNNING")
	}
	for _, q := range []string{
		"SELECT count(*) FROM instances WHERE cleanup!='COMPLETE'",
		"SELECT count(*) FROM create_submissions WHERE state='SUBMITTED'",
		"SELECT count(*) FROM generation_references WHERE kind='live'",
	} {
		var count int
		if err = s.db.QueryRowContext(ctx, q).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return ErrCleanupIncomplete
		}
	}
	pending, err := s.PendingProvisions(ctx)
	if err != nil {
		return err
	}
	for _, p := range pending {
		if p.Kind != "unit" {
			continue
		}
		var desired ProvisionProperties
		if err = gvxcontract.DecodeStrict(p.Desired, 64<<10, 16, &desired); err != nil {
			return err
		}
		if desired.Unit != nil || desired.Name != "" {
			return errors.New("temporary unit provisioning remains unsettled")
		}
	}
	refs, err := s.GenerationReferences(ctx)
	if err != nil {
		return err
	}
	for _, ref := range refs {
		if ref.Kind == "preparation" {
			if err = s.assertRetainedDevelopmentReference(ctx, ref); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) LeaseOwner(ctx context.Context) (UnitIdentity, error) {
	var u UnitIdentity
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key='lease_owner'").Scan(&raw)
	if err == nil {
		err = gvxcontract.DecodeStrict(raw, 64<<10, 8, &u)
	}
	return u, err
}

func createControlAnchor(path string, gid uint32) (*os.File, []ProvisionProperties, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || gid == 0 {
		return nil, nil, invalid("absolute approved control anchor and app GID required")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	current := "/"
	var created []ProvisionProperties
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, name := range parts {
		current = filepath.Join(current, name)
		child, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		made := false
		if errors.Is(e, unix.ENOENT) {
			mode := uint32(0755)
			if i == len(parts)-1 {
				mode = 0710
			}
			if e = unix.Mkdirat(fd, name, mode); e == nil {
				child, e = unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				made = e == nil
			}
		} else if e == nil && i == len(parts)-1 {
			unix.Close(child)
			unix.Close(fd)
			return nil, nil, errors.New("initial control anchor must not preexist")
		}
		if e != nil {
			unix.Close(fd)
			return nil, nil, e
		}
		var st unix.Stat_t
		e = unix.Fstat(child, &st)
		if e == nil && (st.Uid != 0 || st.Mode&0022 != 0) {
			e = errors.New("control ancestor is not trusted root-owned directory")
		}
		if e == nil && made && i == len(parts)-1 {
			e = unix.Fchown(child, 0, int(gid))
			if e == nil {
				e = unix.Fchmod(child, 0710)
			}
			if e == nil {
				e = unix.Fstat(child, &st)
			}
		}
		if e == nil && made {
			created = append(created, ProvisionProperties{Path: current, Dev: uint64(st.Dev), Ino: st.Ino, UID: st.Uid, GID: st.Gid, Mode: st.Mode & 07777, ProductCreated: true})
			e = unix.Fsync(fd)
		}
		unix.Close(fd)
		if e != nil {
			unix.Close(child)
			return nil, nil, e
		}
		fd = child
	}
	return os.NewFile(uintptr(fd), "installation-control-anchor"), created, nil
}

func (s *Store) BackupTo(ctx context.Context, path string) error {
	return s.backupSQLite(ctx, path)
}

func (s *Store) PutDevelopmentRevision(ctx context.Context, r RevisionRecord) error {
	if err := s.requireLease(); err != nil {
		return err
	}
	if !validLedgerID(r.ID) || r.DevelopmentWorker == nil || !validLedgerID(r.DevelopmentWorker.JobID) || !provision.ValidDigest(r.DevelopmentWorker.ArtifactDigest) {
		return invalid("invalid development revision binding")
	}
	s.manifestMu.Lock()
	defer s.manifestMu.Unlock()
	m, err := s.Installation(ctx)
	if err != nil {
		return err
	}
	d := r.DevelopmentWorker
	if m.State != "READY" || d.BaseRevision != m.ActiveRevision {
		return errors.New("development worker base is not active READY release")
	}
	base, err := s.Revision(ctx, d.BaseRevision)
	if err != nil {
		return err
	}
	if base.DevelopmentWorker != nil {
		return errors.New("development revision cannot be a development base")
	}
	base.ID = r.ID
	base.DevelopmentWorker = d
	expected, err := json.Marshal(base)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(raw) > revisionJSONMax || string(expected) != string(raw) {
		return errors.New("development revision must copy exact installed release policy/configuration")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = checkRevisionUsableTx(ctx, tx, r); err != nil {
		return err
	}
	if err = checkGenerationAvailableTx(ctx, tx, "development-worker:"+d.JobID); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, "SELECT record FROM provisioning_ledger WHERE kind='development-worker' AND identity=?", d.JobID)
	if err != nil {
		return err
	}
	committed := false
	for rows.Next() {
		var value []byte
		if err = rows.Scan(&value); err != nil {
			rows.Close()
			return err
		}
		var record ProvisionRecord
		if err = decodeProvisionRecord(value, &record); err != nil {
			rows.Close()
			return err
		}
		if record.State != "OBSERVED" || record.CleanupState == "COMPLETE" {
			continue
		}
		var p ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); err != nil {
			rows.Close()
			return err
		}
		var desired ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); err != nil {
			rows.Close()
			return err
		}
		if desired.Revision != d.BaseRevision {
			continue
		}
		if p.Digest == d.ArtifactDigest && p.Revision == d.BaseRevision && p.ImageSpace != nil && p.ImageSpace.JobID == d.JobID && p.ImageSpace.Source == filepath.Join(m.Paths.StorageRoot, "images", d.JobID) && p.ImageSpace.Cache == filepath.Join(m.Paths.StorageRoot, "prepared", d.JobID) {
			committed = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if !committed {
		return errors.New("development revision has no committed unretired worker ledger")
	}
	generation := "development-worker:" + d.JobID
	var boundClaims int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM storage_generations g JOIN storage_claims c ON c.id=g.claim WHERE g.generation=? AND c.id IN (?,?) AND c.kind IN ('source','cache') AND c.state='RESERVED'", generation, d.JobID+":source", d.JobID+":cache").Scan(&boundClaims); err != nil {
		return err
	}
	if boundClaims != 2 {
		return errors.New("development worker source/cache quota generation is not live")
	}
	var old []byte
	err = tx.QueryRowContext(ctx, "SELECT record FROM revisions WHERE id=?", r.ID).Scan(&old)
	if err == nil {
		if string(old) != string(raw) {
			return errors.New("development revision ID reuse")
		}
		var n int
		err = tx.QueryRowContext(ctx, "SELECT count(*) FROM generation_references WHERE kind='preparation' AND id=? AND claim=?", generation, "dev-revision:"+r.ID).Scan(&n)
		if err != nil {
			return err
		}
		if n != 1 {
			return errors.New("development revision is already retired")
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var uploads int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM generation_references WHERE kind='preparation' AND id=? AND claim=?", generation, "dev-upload:"+d.JobID).Scan(&uploads); err != nil {
		return err
	}
	if uploads != 1 {
		return errors.New("development upload lacks live preparation retention")
	}
	if err = retainGenerationTx(ctx, tx, "preparation", generation, "dev-revision:"+r.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO revisions VALUES(?,?)", r.ID, raw); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM generation_references WHERE kind='preparation' AND id=? AND claim=?", generation, "dev-upload:"+d.JobID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CompleteRecovery(ctx context.Context, e CleanupEvidence) error {
	if err := validateCleanup(e); err != nil {
		return err
	}
	return s.updateInstallation(ctx, func(m *InstallationManifest, tx *sql.Tx) error {
		if m.State != "RECOVERY_REQUIRED" || m.ActiveRevision == "" || m.PendingRevision != "" {
			return errors.New("recovery requires existing release and no pending replacement")
		}
		var active int
		if err := tx.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM instances WHERE cleanup!='COMPLETE')+(SELECT count(*) FROM create_submissions WHERE state='SUBMITTED')").Scan(&active); err != nil {
			return err
		}
		if active != 0 {
			return ErrCleanupIncomplete
		}
		rows, err := tx.QueryContext(ctx, "SELECT record FROM provisioning_ledger WHERE kind='unit'")
		if err != nil {
			return err
		}
		for rows.Next() {
			var raw []byte
			if err = rows.Scan(&raw); err != nil {
				rows.Close()
				return err
			}
			var record ProvisionRecord
			if err = decodeProvisionRecord(raw, &record); err != nil {
				rows.Close()
				return err
			}
			if record.CleanupState == "COMPLETE" {
				continue
			}
			var desired ProvisionProperties
			if err = gvxcontract.DecodeStrict(record.Desired, 64<<10, 16, &desired); err != nil {
				rows.Close()
				return err
			}
			if desired.Name != "" || desired.Unit != nil {
				rows.Close()
				return ErrCleanupIncomplete
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		var raw []byte
		if err = tx.QueryRowContext(ctx, "SELECT record FROM revisions WHERE id=?", m.ActiveRevision).Scan(&raw); err != nil {
			return err
		}
		var revision RevisionRecord
		if err = gvxcontract.DecodeStrict(raw, revisionJSONMax, 32, &revision); err != nil {
			return err
		}
		if revision.DevelopmentWorker != nil || revision.BundleDigest != m.BundleDigest {
			return errors.New("recovery cannot adopt a different release")
		}
		if err = validateRevisionLaunchPolicies(revision); err != nil {
			return err
		}
		if err = retainRevisionTx(ctx, tx, revision); err != nil {
			return err
		}
		m.State = "READY"
		return nil
	})
}

func (s *Store) assertRetainedDevelopmentReference(ctx context.Context, ref GenerationReference) error {
	job := ""
	switch {
	case strings.HasPrefix(ref.Claim, "dev-revision:"):
		revision, err := s.Revision(ctx, strings.TrimPrefix(ref.Claim, "dev-revision:"))
		if err != nil {
			return err
		}
		if revision.DevelopmentWorker == nil {
			return ErrCleanupIncomplete
		}
		job = revision.DevelopmentWorker.JobID
	case strings.HasPrefix(ref.Claim, "dev-upload:"):
		job = strings.TrimPrefix(ref.Claim, "dev-upload:")
	default:
		return ErrCleanupIncomplete
	}
	if !validLedgerID(job) || ref.ID != "development-worker:"+job {
		return ErrCleanupIncomplete
	}
	var released int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM storage_claims WHERE id=? AND kind='preparation' AND state='RELEASED'", job+":preparation").Scan(&released); err != nil {
		return err
	}
	if released != 1 {
		return ErrCleanupIncomplete
	}
	rows, err := s.db.QueryContext(ctx, "SELECT record FROM provisioning_ledger WHERE kind='development-worker' AND identity=?", job)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return err
		}
		var record ProvisionRecord
		if err = decodeProvisionRecord(raw, &record); err != nil {
			return err
		}
		if record.State != "OBSERVED" || record.CleanupState == "COMPLETE" {
			continue
		}
		var p ProvisionProperties
		if err = gvxcontract.DecodeStrict(record.Observed.Attributes, 64<<10, 16, &p); err != nil {
			return err
		}
		if p.ImageSpace != nil && p.ImageSpace.JobID == job && provision.ValidDigest(p.Digest) {
			return nil
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	return ErrCleanupIncomplete
}
