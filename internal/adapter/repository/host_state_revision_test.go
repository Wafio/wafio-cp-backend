package repository

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDesiredStateRevisionNoFloatRounding(t *testing.T) {
	for _, raw := range []string{`{"_revision":"1789130380174837001"}`, `{"_revision":1789130380174837001}`} {
		revision, err := DesiredStateRevision([]byte(raw))
		if err != nil || revision != 1789130380174837001 {
			t.Fatalf("revision %d %v", revision, err)
		}
	}
	for _, raw := range []string{`{"_revision":1.5}`, `{"_revision":"-1"}`, `{"_revision":"overflow"}`} {
		if _, err := DesiredStateRevision([]byte(raw)); err == nil {
			t.Fatal("invalid revision accepted")
		}
	}
}

func TestDesiredStateConcurrentCASAndCounterIsolation(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "host_revision_" + uuid.NewString()[:8]
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `CREATE TABLE agents(id text PRIMARY KEY,project_id text,desired_state jsonb,deleted_at timestamptz);INSERT INTO agents VALUES('a','p','{}')`); err != nil {
		t.Fatal(err)
	}
	repo := &EBPFRepo{pool: pool}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, raw := range []string{`{"config":{"enabled":true}}`, `{"config":{"enabled":false}}`} {
		wg.Add(1)
		go func(raw string) {
			defer wg.Done()
			_, err := repo.CompareAndSwapDesiredState(ctx, "p", "a", 0, json.RawMessage(raw))
			results <- err
		}(raw)
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrDesiredStateConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success %d conflict %d", success, conflict)
	}
	first, err := repo.GetDesiredState(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	revision, _ := DesiredStateRevision(first)
	next, err := repo.CompareAndSwapDesiredState(ctx, "p", "a", revision, json.RawMessage(`{"config":{"enabled":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SetDesiredState(ctx, "p", "a", first); !errors.Is(err, ErrDesiredStateConflict) {
		t.Fatalf("stale counters overwrote config: %v", err)
	}
	if err := repo.SetDesiredState(ctx, "p", "a", next); err != nil {
		t.Fatal(err)
	}
	final, _ := repo.GetDesiredState(ctx, "a")
	nextRevision, _ := DesiredStateRevision(next)
	finalRevision, _ := DesiredStateRevision(final)
	if finalRevision != nextRevision || nextRevision <= revision {
		t.Fatal("counter write changed revision or config revision regressed")
	}
}
