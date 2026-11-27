//go:build linux

package host

import (
	"bytes"
	"context"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/thirdscam/chatanium/internal/bundle"
	"golang.org/x/sys/unix"
)

func TestPreparationIDMapRejectsAliasesAndRanges(t *testing.T) {
	good := "         0          0          1\n      1201       1201          1\n"
	want := [2]PreparationIDMap{{Inside: 0, Outside: 0, Length: 1}, {Inside: 1201, Outside: 1201, Length: 1}}
	got, err := parsePreparationIDMap([]byte(good), 1201)
	if err != nil || got != want {
		t.Fatalf("exact native map: %v, %v", got, err)
	}
	for _, raw := range []string{
		"0 0 1\n", "0 0 1\n1201 1202 1\n", "0 0 1\n1201 1201 2\n",
		"0 0 1\n1201 1201 1\n1202 1202 1\n", "1201 1201 1\n0 0 1\n",
		"0 0 4294967296\n1201 1201 1\n", "0 0 1\n1201 1201 1 extra\n",
	} {
		if _, err := parsePreparationIDMap([]byte(raw), 1201); err == nil {
			t.Errorf("accepted extra/aliased map %q", raw)
		}
	}
}

func TestPreparationUserNamespaceRequiresRootDirectChild(t *testing.T) {
	host := NamespaceIdentity{Device: 4, Inode: 20}
	child := NamespaceIdentity{Device: 4, Inode: 21}
	if err := validatePreparationUserNamespace(child, host, host, unix.CLONE_NEWUSER, 0); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name                string
		child, parent, host NamespaceIdentity
		typ, owner          uint32
	}{
		{"host namespace", host, host, host, unix.CLONE_NEWUSER, 0},
		{"untrusted intermediate", child, NamespaceIdentity{Device: 4, Inode: 22}, host, unix.CLONE_NEWUSER, 0},
		{"same UID owner", child, host, host, unix.CLONE_NEWUSER, 1201},
		{"wrong namespace type", child, host, host, unix.CLONE_NEWNS, 0},
		{"missing identity", NamespaceIdentity{}, host, host, unix.CLONE_NEWUSER, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validatePreparationUserNamespace(test.child, test.parent, test.host, test.typ, test.owner); err == nil {
				t.Fatal("admitted an outside writer domain")
			}
		})
	}
}

func TestPreparationTaskRejectsExtraAuthority(t *testing.T) {
	const status = "Uid:\t1201\t1201\t1201\t1201\nGid:\t1301\t1301\t1301\t1301\nGroups:\t1301 1301\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t3\n"
	identity := NumericIdentity{UID: 1201, GID: 1301}
	got, err := parsePreparationTask([]byte(status), identity)
	if err != nil || got.UIDs != [4]uint32{1201, 1201, 1201, 1201} || got.SupplementaryGID != 1301 || got.SupplementaryGroupCount != 2 || got.SeccompFilters != 3 {
		t.Fatalf("native primary-GID-only task: %+v, %v", got, err)
	}
	for _, change := range [][2]string{
		{"Groups:\t1301 1301", "Groups:\t1301 1302"},
		{"Uid:\t1201\t1201\t1201\t1201", "Uid:\t1201\t1201\t1201\t0"},
		{"CapBnd:\t0000000000000000", "CapBnd:\t0000000000000001"},
		{"NoNewPrivs:\t1", "NoNewPrivs:\t0"},
		{"Seccomp_filters:\t3\n", ""},
	} {
		if _, err := parsePreparationTask([]byte(strings.Replace(status, change[0], change[1], 1)), identity); err == nil {
			t.Errorf("accepted authority mutation %q", change[1])
		}
	}
}

func TestPreparationFilterTransitionRequiresOneNewFilter(t *testing.T) {
	before := PreparationTaskSnapshot{ThreadCount: 2, UIDs: [4]uint32{1201, 1201, 1201, 1201}, GIDs: [4]uint32{1301, 1301, 1301, 1301}, NoNewPrivileges: true, SeccompMode: 2, SeccompFilters: 3}
	after := before
	after.ThreadCount = 3 // New threads inherit the TSYNC-installed chain.
	after.SnapshotDigest = "new native snapshot"
	after.SeccompFilters++
	if err := validatePreparationFilterTransition(before, after); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name          string
		before, after PreparationTaskSnapshot
	}{
		{"ack without filter", before, before},
		{"two filters", before, func() PreparationTaskSnapshot { v := after; v.SeccompFilters++; return v }()},
		{"mode without filter", before, func() PreparationTaskSnapshot { v := after; v.SeccompMode = 0; return v }()},
		{"credential drift", before, func() PreparationTaskSnapshot { v := after; v.UIDs[3] = 0; return v }()},
		{"counter wrap", func() PreparationTaskSnapshot { v := before; v.SeccompFilters = math.MaxUint32; return v }(), after},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validatePreparationFilterTransition(test.before, test.after); err == nil {
				t.Fatal("accepted unproven filter installation")
			}
		})
	}
}

func TestPreparationCompleteReplayKeepsCurrentBootAndImmutableHistory(t *testing.T) {
	fixture := newPreparationWriterFixture(t)
	fixture.settleFull(t)
	ctx := context.Background()
	store := fixture.create.journal
	historical := fixture.settlement(t)
	if err := store.CompleteProvisionCleanup(ctx, fixture.internal, historical); err != nil {
		t.Fatal(err)
	}
	var before []byte
	if err := store.db.QueryRowContext(ctx, "SELECT record FROM provisioning_ledger WHERE id=?", fixture.internal).Scan(&before); err != nil {
		t.Fatal(err)
	}

	// The existing invocation belongs to a previous boot. The caller has just
	// collected current scoped absence; replay must validate, not substitute,
	// the immutable settlement from that earlier boot.
	currentBoot := "current-boot-after-complete"
	unit := fixture.writer.Birth.Unit
	current := CleanupEvidence{
		BootID: currentBoot, Units: []UnitIdentity{unit},
		JobsAbsent: true, ProcessesAbsent: true, TransportsClosed: true,
		MountsAbsent: true, OpenReferencesAbsent: true,
		Details: writerTestJSON(t, UnitAbsenceDetails{
			UnitAbsent: true, CgroupEmpty: true, TransportPipes: fixture.internalBirth.TransportPipes,
		}),
	}
	expected := current
	expected.Details = writerTestJSON(t, UnitAbsenceDetails{
		UnitAbsent: true, CgroupEmpty: true, TransportPipes: fixture.internalBirth.TransportPipes,
		WriterUserNamespace: &fixture.writer.Birth.UserNamespace, WriterUserNamespaceAbsent: true,
	})
	d := &Systemd{store: store, boot: currentBoot}
	ref := &systemdReference{
		unit: unit, service: OwnedService{Program: bundle.Preparer},
		intent: fixture.internal, pipes: fixture.internalBirth.TransportPipes,
	}
	if err := d.persistPreparationSettlement(ctx, ref, &current); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(current, expected) {
		t.Fatalf("COMPLETE replay replaced current native absence: got %+v, want %+v", current, expected)
	}
	if current.BootID == historical.BootID {
		t.Fatal("returned historical boot instead of the current observation")
	}
	var after []byte
	if err := store.db.QueryRowContext(ctx, "SELECT record FROM provisioning_ledger WHERE id=?", fixture.internal).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("COMPLETE replay rewrote immutable provisioning history")
	}
}
