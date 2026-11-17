package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5"
)

// perChunkIndex is a hypertable index that must be built one chunk per
// transaction (TimescaleDB `transaction_per_chunk`). That statement cannot
// run in a transaction block, a DO block or a function, and plain PostgreSQL
// rejects the option, so it cannot live in a migration file that has to work
// with and without TimescaleDB. The migration that introduces the index
// builds it itself on a plain table and leaves the hypertable case to
// ensurePerChunkIndexes, which runs after every `migrate up`.
type perChunkIndex struct {
	sinceVersion uint // schema version that introduced the index
	table        string
	name         string
	create       string // single statement, run outside any transaction
}

var perChunkIndexes = []perChunkIndex{{
	sinceVersion: 89,
	table:        "waf_decisions",
	name:         "waf_decisions_app_id_recorded_at",
	create: `CREATE INDEX IF NOT EXISTS waf_decisions_app_id_recorded_at
    ON waf_decisions (app_id, recorded_at DESC)
    WITH (timescaledb.transaction_per_chunk)`,
}, {
	sinceVersion: 109, // false-positive feedback summary
	table:        "waf_decisions",
	name:         "waf_decisions_flagged_agent_recorded_at",
	create: `CREATE INDEX IF NOT EXISTS waf_decisions_flagged_agent_recorded_at
    ON waf_decisions (agent_id, recorded_at DESC)
    INCLUDE (action, app_id, analyze_method, categories)
    WITH (timescaledb.transaction_per_chunk)
    WHERE action IN ('block', 'log', 'monitor')`,
}}

// ensurePerChunkIndexesAfter reads the schema version from m and builds the
// per-chunk indexes it calls for.
func ensurePerChunkIndexesAfter(m *migrate.Migrate, dsn string) error {
	version, dirty, err := m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return nil
	}
	if err != nil {
		return err
	}
	if dirty {
		return fmt.Errorf("schema version %d is dirty; per-chunk indexes not built", version)
	}
	return ensurePerChunkIndexes(context.Background(), dsn, version)
}

// ensurePerChunkIndexes builds every per-chunk index whose migration is
// applied (version >= sinceVersion) on tables that are TimescaleDB
// hypertables. A valid existing index is left alone; an invalid one (an
// interrupted per-chunk build) is dropped and rebuilt. Plain tables are
// skipped: their migration already built the index.
func ensurePerChunkIndexes(ctx context.Context, dsn string, version uint) error {
	var todo []perChunkIndex
	for _, ix := range perChunkIndexes {
		if version >= ix.sinceVersion {
			todo = append(todo, ix)
		}
	}
	if len(todo) == 0 {
		return nil
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(ctx) }()
	for _, ix := range todo {
		if err := ensurePerChunkIndex(ctx, conn, ix); err != nil {
			return fmt.Errorf("index %s: %w", ix.name, err)
		}
	}
	return nil
}

func ensurePerChunkIndex(ctx context.Context, conn *pgx.Conn, ix perChunkIndex) error {
	hyper, err := isHypertable(ctx, conn, ix.table)
	if err != nil || !hyper {
		return err
	}
	var valid *bool
	err = conn.QueryRow(ctx, `
		SELECT i.indisvalid FROM pg_index i
		  JOIN pg_class c ON c.oid = i.indexrelid
		 WHERE c.relname = $1 AND c.relnamespace = current_schema()::regnamespace`, ix.name).Scan(&valid)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return err
	case valid != nil && *valid:
		return nil
	default:
		log.Printf("migrate: index %s is invalid (interrupted build); rebuilding", ix.name)
		if _, err := conn.Exec(ctx, "DROP INDEX IF EXISTS "+pgx.Identifier{ix.name}.Sanitize()); err != nil {
			return err
		}
	}
	start := time.Now()
	log.Printf("migrate: building %s on hypertable %s, one chunk per transaction", ix.name, ix.table)
	// No arguments: pgx sends one simple-protocol query, so the statement is
	// not inside a transaction block.
	if _, err := conn.Exec(ctx, ix.create); err != nil {
		return err
	}
	log.Printf("migrate: %s built in %s", ix.name, time.Since(start).Round(time.Millisecond))
	return nil
}

// isHypertable reports whether table (in the current schema) is a
// TimescaleDB hypertable; false when the extension is not installed.
func isHypertable(ctx context.Context, conn *pgx.Conn, table string) (bool, error) {
	var hasTS bool
	if err := conn.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')`).Scan(&hasTS); err != nil || !hasTS {
		return false, err
	}
	var hyper bool
	err := conn.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM timescaledb_information.hypertables
		                WHERE hypertable_name = $1 AND hypertable_schema = current_schema())`, table).Scan(&hyper)
	return hyper, err
}
