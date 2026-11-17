package repository

import (
	"context"
	"os"
	"testing"
	"time"
)

// Every telemetry table is a TimescaleDB hypertable on its
// time column, in 1-day chunks, with a retention policy (migrations
// 000048–000051). Needs a migrated database with the timescaledb extension
// (the database-integration CI job); plain PostgreSQL skips, since the
// migrations only create hypertables when the extension is present.
func TestDBTelemetryTablesAreHypertablesWithRetention(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := context.Background()
	repo, err := New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	var hasTS bool
	if err := repo.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')`).Scan(&hasTS); err != nil {
		t.Fatal(err)
	}
	if !hasTS {
		t.Skip("timescaledb extension not installed")
	}

	want := []struct {
		table, timeCol string
		retention      time.Duration
	}{
		{"waf_decisions", "recorded_at", 30 * 24 * time.Hour},
		{"host_security_events", "event_time", 7 * 24 * time.Hour},
		{"host_fw_features", "ts", 30 * 24 * time.Hour},
		{"host_sec_features", "ts", 30 * 24 * time.Hour},
		{"host_enforcement_events", "event_time", 30 * 24 * time.Hour},
	}
	for _, w := range want {
		var col string
		var chunkSec int64
		err := repo.DB.QueryRow(ctx, `
			SELECT d.column_name, EXTRACT(EPOCH FROM d.time_interval)::bigint
			  FROM timescaledb_information.dimensions d
			 WHERE d.hypertable_schema = current_schema()
			   AND d.hypertable_name = $1
			   AND d.dimension_number = 1`, w.table).Scan(&col, &chunkSec)
		if err != nil {
			t.Errorf("%s: not a hypertable: %v", w.table, err)
			continue
		}
		if chunk := time.Duration(chunkSec) * time.Second; col != w.timeCol || chunk != 24*time.Hour {
			t.Errorf("%s: partitioned on %s every %v, want %s every 24h", w.table, col, chunk, w.timeCol)
		}

		var dropSec int64
		err = repo.DB.QueryRow(ctx, `
			SELECT EXTRACT(EPOCH FROM (j.config->>'drop_after')::interval)::bigint
			  FROM timescaledb_information.jobs j
			 WHERE j.proc_name = 'policy_retention'
			   AND j.hypertable_schema = current_schema()
			   AND j.hypertable_name = $1`, w.table).Scan(&dropSec)
		if err != nil {
			t.Errorf("%s: no retention policy: %v", w.table, err)
			continue
		}
		if dropAfter := time.Duration(dropSec) * time.Second; dropAfter != w.retention {
			t.Errorf("%s: retention %v, want %v", w.table, dropAfter, w.retention)
		}
	}
}
