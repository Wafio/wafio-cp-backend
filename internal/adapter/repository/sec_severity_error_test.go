package repository

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A failed severity query used to return empty counts and a nil
// error, so the dashboard showed zero findings instead of falling back.
func TestSecFeatureSeverityCountsReturnsQueryError(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://u:p@127.0.0.1:1/db?connect_timeout=1&sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s := &HostEventStore{pool: pool}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, _, err := s.QuerySecFeatureSeverityCounts(ctx, "a1", 60); err == nil {
		t.Fatal("QuerySecFeatureSeverityCounts swallowed the error")
	}
	if _, _, err := s.QuerySecFeatureSeverityCountsMulti(ctx, []string{"a1"}, 60); err == nil {
		t.Fatal("QuerySecFeatureSeverityCountsMulti swallowed the error")
	}
}
