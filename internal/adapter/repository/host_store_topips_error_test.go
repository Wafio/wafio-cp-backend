package repository

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestQueryFWFeatureTopIPsRangeReturnsDatabaseError(t *testing.T) {
	ctx := t.Context()
	pool, err := pgxpool.New(ctx, "postgres://test:test@localhost:5432/unused")
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	rows, err := NewHostEventStore(pool).QueryFWFeatureTopIPsRange(ctx, []string{"agent-id"}, 0, 20)
	if err == nil || len(rows) != 0 {
		t.Fatalf("closed database returned %d rows and error %v; want database error", len(rows), err)
	}
}
