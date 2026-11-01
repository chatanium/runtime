package Database

import (
	"context"
	"database/sql"
	"fmt"

	embed "github.com/thirdscam/chatanium/database"
	"github.com/thirdscam/chatanium/src/Database/Internal"
	_ "modernc.org/sqlite"
)

// DB is the host-owned, process-local recording database.
type DB struct {
	Conn    *sql.DB
	Queries *Internal.Queries
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
	if _, err := conn.ExecContext(ctx, embed.DDL); err != nil {
		conn.Close()
		return fmt.Errorf("initialize host database: %w", err)
	}
	t.Conn = conn
	t.Queries = Internal.New(conn)
	return nil
}

// Shutdown is called only after host callbacks have been detached and drained.
func (t *DB) Shutdown() error {
	if t.Conn == nil {
		return nil
	}
	return t.Conn.Close()
}
