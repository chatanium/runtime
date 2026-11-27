package store

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/thirdscam/chatanium/internal/discordacl"
	"github.com/thirdscam/chatanium/internal/gvxcontract"
)

const maxDiscordACLBytes = 64 << 10

type DiscordACLRecord struct {
	Binding string
	Policy  discordacl.Policy
}

func (s *Store) DiscordACLs(ctx context.Context) (map[string]DiscordACLRecord, error) {
	var exists bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='discord_acl')`).Scan(&exists); err != nil || !exists {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT acl.module_id, acl.binding, acl.policy FROM discord_acl acl JOIN approvals a USING(module_id) LIMIT 513`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]DiscordACLRecord)
	for rows.Next() {
		var id string
		var entry DiscordACLRecord
		var raw []byte
		if err := rows.Scan(&id, &entry.Binding, &raw); err != nil {
			return nil, err
		}
		if len(result) >= 512 || !validDigest(entry.Binding) || gvxcontract.DecodeStrict(raw, maxDiscordACLBytes, 8, &entry.Policy) != nil || entry.Policy.Validate() != nil {
			return nil, ErrApprovalMismatch
		}
		result[id] = entry
	}
	return result, rows.Err()
}

func (s *Store) SetDiscordACL(ctx context.Context, epoch, revision, module string, entry DiscordACLRecord) error {
	raw, err := json.Marshal(entry.Policy)
	if err != nil || len(raw) > maxDiscordACLBytes || !validDigest(entry.Binding) || entry.Policy.Validate() != nil {
		return ErrInvalid
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		current, err := requireEpoch(ctx, tx, epoch)
		if err != nil {
			return err
		}
		if current.State != Ready || current.Desired != DesiredRunning || !current.WorkerPending || current.ConfigRevision != revision {
			return ErrState
		}
		var installed bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM approvals WHERE module_id=?)`, module).Scan(&installed); err != nil {
			return err
		}
		if !installed {
			return ErrApprovalMismatch
		}
		if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS discord_acl (
			module_id TEXT PRIMARY KEY NOT NULL,
			binding TEXT NOT NULL,
			policy BLOB NOT NULL CHECK(length(policy)>0 AND length(policy)<=65536)
		) STRICT`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM discord_acl WHERE module_id NOT IN (SELECT module_id FROM approvals)`); err != nil {
			return err
		}
		return exactlyOne(tx.ExecContext(ctx, `INSERT INTO discord_acl VALUES (?,?,?)
			ON CONFLICT(module_id) DO UPDATE SET binding=excluded.binding, policy=excluded.policy`, module, entry.Binding, raw))
	})
}
