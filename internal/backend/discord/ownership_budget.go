package discordbackend

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"io"
	"net/url"
	"os"
	"strconv"
)

const (
	// PortableOwnershipBudgetBytes is reserved for one main ownership database
	// and its one DELETE rollback journal, including sector overhead. With
	// cache spill disabled, the journal saves at most one before-image per
	// original page (plus 8 bytes per image and one sector-aligned header).
	PortableOwnershipBudgetBytes = 80 << 20
	portableOwnershipMainBytes   = 32 << 20
	portableOwnershipPageBytes   = 4096
	portableOwnershipPages       = portableOwnershipMainBytes / portableOwnershipPageBytes
	portableOwnershipJournalMax  = PortableOwnershipBudgetBytes - portableOwnershipMainBytes
)

var rollbackJournalMagic = [8]byte{0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7}

func portableOwnershipQuery() string {
	q := url.Values{
		"mode":          {"rw"},
		"cache":         {"private"},
		"_journal_mode": {"DELETE"},
		"_synchronous":  {"FULL"},
		"_foreign_keys": {"ON"},
		"_pragma": {
			"page_size(" + strconv.Itoa(portableOwnershipPageBytes) + ")",
			"max_page_count(" + strconv.Itoa(portableOwnershipPages) + ")",
			"cache_spill(OFF)",
			"temp_store(MEMORY)",
		},
	}
	return q.Encode()
}

// DSN settings also apply on reconnect; startup verifies the effective values
// before executing any schema or ownership writes.
func verifyPortableOwnershipSQLite(db *sql.DB) error {
	for _, setting := range [...]struct {
		query string
		value int
	}{
		{"PRAGMA page_size", portableOwnershipPageBytes},
		{"PRAGMA max_page_count", portableOwnershipPages},
		{"PRAGMA cache_spill", 0},
		{"PRAGMA temp_store", 2},
	} {
		var actual int
		if err := db.QueryRow(setting.query).Scan(&actual); err != nil {
			return err
		}
		if actual != setting.value {
			return errors.New("portable Discord ownership SQLite budget settings were not applied")
		}
	}
	var mode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		return err
	}
	if mode != "delete" {
		return errors.New("portable Discord ownership SQLite requires DELETE rollback mode")
	}
	return nil
}

// Authorize the storage geometry before SQLite opens the file: WAL and page
// size are recorded in the database header, and SQLite may recover the hot
// journal while applying the first PRAGMA (before max_page_count takes effect).
func validatePortableOwnershipDatabase(file *os.File, size int64) error {
	if size == 0 {
		return nil // The securely precreated, uninitialized database.
	}
	if size > portableOwnershipMainBytes || size%portableOwnershipPageBytes != 0 {
		return errors.New("portable Discord ownership database has unreserved size")
	}
	var header [20]byte
	if _, err := file.ReadAt(header[:], 0); err != nil {
		return err
	}
	if string(header[:16]) != "SQLite format 3\x00" || binary.BigEndian.Uint16(header[16:18]) != portableOwnershipPageBytes || header[18] != 1 || header[19] != 1 {
		return errors.New("portable Discord ownership database has unsupported SQLite geometry")
	}
	return nil
}

func validatePortableOwnershipJournal(file *os.File, size int64) error {
	if size > portableOwnershipJournalMax {
		return errors.New("portable Discord ownership rollback journal has unreserved size")
	}
	if size < int64(len(rollbackJournalMagic)) {
		return nil // SQLite cannot replay a partial magic header.
	}
	var tail [8]byte
	if _, err := file.ReadAt(tail[:], size-int64(len(tail))); err != nil {
		return err
	}
	if size >= 16 && tail == rollbackJournalMagic {
		return errors.New("portable Discord ownership journal cannot name a super-journal")
	}
	var header [28]byte
	n, err := file.ReadAt(header[:], 0)
	if err != nil && err != io.EOF {
		return err
	}
	if [8]byte(header[:8]) != rollbackJournalMagic {
		return nil // An unsynced/cold journal is not replayed.
	}
	if n != len(header) || binary.BigEndian.Uint32(header[16:20]) > portableOwnershipPages || binary.BigEndian.Uint32(header[24:28]) != portableOwnershipPageBytes {
		return errors.New("portable Discord ownership journal could restore an unreserved database")
	}
	return nil
}
