package domain

import (
	"context"
	"time"
)

// Telemetry data retention and database size.
//
// The five telemetry tables are TimescaleDB hypertables when TimescaleDB is
// installed (migrations 000048–000051) and plain tables otherwise. Their
// retention is a TimescaleDB retention policy where one can exist; elsewhere
// the control plane deletes old rows itself (application.Storage).

// RetentionTable describes one telemetry table under managed retention.
type RetentionTable struct {
	// Name is the SQL table name (a fixed identifier, never user input).
	Name string
	// Label is the name shown to operators.
	Label string
	// TimeColumn is the hypertable's partitioning column; retention drops
	// rows (chunks) older than the retention by this column.
	TimeColumn string
	// DefaultDays is the retention the migrations install.
	DefaultDays int
	// MinDays is the shortest retention an administrator can set.
	MinDays int
}

// RetentionMaxDays is the longest retention an administrator can set.
const RetentionMaxDays = 3650

// RetentionTables are the managed tables, in display order. Minimums: two
// days for host_security_events (the largest table; above the one-day
// compression window of migration 000112, so a chunk is compressed before
// it is dropped), seven days for the others (the dashboard's 7-day ranges
// and the host analytics read them).
var RetentionTables = []RetentionTable{
	{Name: "waf_decisions", Label: "WAF decisions", TimeColumn: "recorded_at", DefaultDays: 30, MinDays: 7},
	{Name: "host_security_events", Label: "Runtime security events", TimeColumn: "event_time", DefaultDays: 7, MinDays: 2},
	{Name: "host_enforcement_events", Label: "Host enforcement events", TimeColumn: "event_time", DefaultDays: 30, MinDays: 7},
	{Name: "host_fw_features", Label: "Firewall feature aggregates", TimeColumn: "ts", DefaultDays: 30, MinDays: 7},
	{Name: "host_sec_features", Label: "Runtime security aggregates", TimeColumn: "ts", DefaultDays: 30, MinDays: 7},
}

// RetentionTableByName returns the managed table of that name.
func RetentionTableByName(name string) (RetentionTable, bool) {
	for _, t := range RetentionTables {
		if t.Name == name {
			return t, true
		}
	}
	return RetentionTable{}, false
}

// TimescaleInfo is the TimescaleDB extension of the connected database.
type TimescaleInfo struct {
	// Installed is false on a plain PostgreSQL.
	Installed bool
	// Version is extversion ("2.30.1"); License is timescaledb.license
	// ("timescale" = community, "apache" = Apache-only).
	Version string
	License string
}

// StorageChunk is one hypertable chunk with its on-disk size.
type StorageChunk struct {
	Start      time.Time
	End        time.Time
	Compressed bool
	Bytes      int64
}

// RetentionPolicy is the TimescaleDB retention job of one hypertable.
type RetentionPolicy struct {
	Exists    bool
	JobID     int
	DropAfter time.Duration
	// Scheduled is false for a paused job.
	Scheduled bool
	// LastSuccess is the last successful finish; LastStatus the last run's
	// status ("Success", "Failed", "" before the first run).
	LastSuccess *time.Time
	LastStatus  string
}

// TableStorageStats is the size and age of one telemetry table.
type TableStorageStats struct {
	Exists     bool
	Hypertable bool
	TotalBytes int64
	// Compression (hypertables): CompressAfter is the compression policy's
	// window (0 = no policy); the byte counts cover compressed chunks only
	// and are 0 when none is compressed yet.
	CompressionEnabled bool
	CompressAfter      time.Duration
	CompressedChunks   int
	BeforeBytes        int64
	AfterBytes         int64
	// Chunks of a hypertable, oldest first.
	Chunks []StorageChunk
	// OldestRow is the oldest time value of a plain table (nil when empty
	// or when the bounded query timed out).
	OldestRow *time.Time
	Retention RetentionPolicy
}

// RetentionApply is one change of a TimescaleDB retention policy.
type RetentionApply struct {
	Table string
	Days  int
}

// StorageStore reads table sizes and changes retention (repository.StorageRepo).
type StorageStore interface {
	TimescaleInfo(ctx context.Context) (TimescaleInfo, error)
	// TableStats reads one table; withOldestRow runs a bounded min() of the
	// time column on a plain table (hypertables use their chunks).
	TableStats(ctx context.Context, t RetentionTable, withOldestRow bool) (TableStorageStats, error)
	// ApplyRetention replaces the retention policies of the listed
	// hypertables and, when settingsKey is not "", upserts that
	// system_settings row, all in one transaction.
	ApplyRetention(ctx context.Context, changes []RetentionApply, settingsKey string, settingsValue any) error
	// DropChunksOlderThan drops hypertable chunks older than days
	// (TimescaleDB drop_chunks, Apache-licensed, against the database
	// clock) and returns how many. days outside 1–RetentionMaxDays is an
	// error.
	DropChunksOlderThan(ctx context.Context, table string, days int) (int, error)
	// DeleteOlderThan deletes at most limit rows of a plain table older
	// than days (cutoff now() - days on the database clock) and returns how
	// many. days outside 1–RetentionMaxDays is an error.
	DeleteOlderThan(ctx context.Context, t RetentionTable, days int, limit int) (int64, error)
	// DatabaseSize is pg_database_size of the connected database.
	DatabaseSize(ctx context.Context) (int64, error)
	// DataDirectory is the server's data_directory setting (needs superuser
	// or pg_read_all_settings; an error otherwise).
	DataDirectory(ctx context.Context) (string, error)
	// AdminEmails are the addresses of the system administrators.
	AdminEmails(ctx context.Context) ([]string, error)
	// TryRetentionLock takes the cluster-wide retention job lock; ok false
	// when another process holds it. release is never nil.
	TryRetentionLock(ctx context.Context) (release func(), ok bool, err error)
}

// SettingsStore persists JSON settings (repository.SystemSettingsRepo).
type SettingsStore interface {
	GetJSON(ctx context.Context, key string, dst any) error
	SetJSON(ctx context.Context, key string, value any) error
}
