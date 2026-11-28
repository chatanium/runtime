package recording

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMemoryDatabaseSharesSchemaAcrossConcurrentCallbacks(t *testing.T) {
	var store DB
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer store.Shutdown()
	if got := store.Conn.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("memory database connection limit = %d, want 1", got)
	}
	var workers sync.WaitGroup
	failures := make(chan error, 8)
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			var count int
			failures <- store.Conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM messages").Scan(&count)
		}()
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
}
