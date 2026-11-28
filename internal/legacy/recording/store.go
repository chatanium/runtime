package recording

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"math/big"

	"github.com/thirdscam/chatanium/internal/legacy/recording/internal/sqlcgen"
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var ddl string

// DB is the host-owned, process-local recording database.
type DB struct {
	Conn    *sql.DB
	Queries *sqlcgen.Queries
}

func (t *DB) Start(ctx context.Context) error {
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return fmt.Errorf("open host database: %w", err)
	}
	// Each SQLite :memory: connection has its own database. Keep the schema and
	// all concurrent Gateway callbacks on the same connection for its lifetime.
	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)
	if _, err := conn.ExecContext(ctx, ddl); err != nil {
		conn.Close()
		return fmt.Errorf("initialize host database: %w", err)
	}
	t.Conn = conn
	t.Queries = sqlcgen.New(conn)
	return nil
}

// Shutdown is called only after host callbacks have been detached and drained.
func (t *DB) Shutdown() error {
	if t.Conn == nil {
		return nil
	}
	return t.Conn.Close()
}

func snowflakeID(id string) int64 {
	var n big.Int
	if _, ok := n.SetString(id, 10); !ok {
		panic("invalid Discord snowflake")
	}
	return n.Int64()
}
