package store

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *Store) Usage(ctx context.Context) (Usage, error) {
	u, err := readUsage(ctx, s.db)
	return u, translate(err)
}

func readUsage(ctx context.Context, q rowReader) (Usage, error) {
	var u Usage
	err := q.QueryRowContext(ctx, `SELECT budget_bytes,metadata_bytes,
		coalesce((SELECT sum(max_bytes) FROM volumes),0),
		coalesce((SELECT sum(scratch_bytes) FROM runs),0),
		coalesce((SELECT sum(max_bytes) FROM preparations),0),
		coalesce((SELECT sum(max_bytes) FROM images),0),
		coalesce((SELECT sum(log_bytes) FROM runs),0),
		coalesce((SELECT sum(max_bytes) FROM backups),0) FROM installation WHERE singleton=1`).Scan(
		&u.BudgetBytes, &u.MetadataBytes, &u.PersistentBytes, &u.ScratchBytes,
		&u.PreparationBytes, &u.CacheBytes, &u.LogBytes, &u.BackupBytes)
	return u, err
}

// admitBytes is called in the same immediate transaction as the new rows or
// increased maxima. Pending rows count the same as active rows. Check by
// subtraction so even near-MaxInt64 user budgets cannot wrap.
func admitBytes(ctx context.Context, tx *sql.Tx, charges ...int64) error {
	u, err := readUsage(ctx, tx)
	if err != nil {
		return err
	}
	left := u.BudgetBytes
	for _, charge := range [...]int64{u.MetadataBytes, u.PersistentBytes, u.ScratchBytes, u.PreparationBytes, u.CacheBytes, u.LogBytes, u.BackupBytes} {
		if charge < 0 || charge > left {
			return fmt.Errorf("%w: existing portable-v2 ledger over budget", ErrBudgetExceeded)
		}
		left -= charge
	}
	for _, charge := range charges {
		if charge < 0 || charge > left {
			return fmt.Errorf("%w: requested %d bytes, %d remaining", ErrBudgetExceeded, charge, left)
		}
		left -= charge
	}
	return nil
}

func collect[T any](ctx context.Context, q queryReader, statement string, scan func(scanner) (T, error), args ...any) ([]T, error) {
	rows, err := q.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []T
	for rows.Next() {
		record, err := scan(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}
