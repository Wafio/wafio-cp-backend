package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// StorageRepo reads telemetry table sizes and manages their retention
// (domain.StorageStore). Table names are fixed
// identifiers from domain.RetentionTables: they reach SQL either as a
// parameter (::regclass, catalog filters) or through the literal per-table
// statements in plainTableSQL — never formatted into a query.
type StorageRepo struct {
	pool *pgxpool.Pool
}

// NewStorageRepo returns a StorageRepo on pool.
func NewStorageRepo(pool *pgxpool.Pool) *StorageRepo { return &StorageRepo{pool: pool} }

var _ domain.StorageStore = (*StorageRepo)(nil)

// plainTableStatements are the statements on one telemetry table that need
// its identifiers (written out, one set per table).
type plainTableStatements struct {
	// oldest is min(time column), for plain tables only.
	oldest string
	// deleteBatch deletes at most $2 rows older than $1 days on the
	// database clock (plain tables).
	deleteBatch string
}

// plainTableSQL holds the statements per managed table
// (TestPlainTableSQLMatchesRetentionTables keeps it in step with
// domain.RetentionTables).
var plainTableSQL = map[string]plainTableStatements{
	"waf_decisions": {
		oldest:      `SELECT min(recorded_at) FROM waf_decisions`,
		deleteBatch: `DELETE FROM waf_decisions WHERE ctid = ANY (ARRAY(SELECT ctid FROM waf_decisions WHERE recorded_at < now() - make_interval(days => $1::int) LIMIT $2))`,
	},
	"host_security_events": {
		oldest:      `SELECT min(event_time) FROM host_security_events`,
		deleteBatch: `DELETE FROM host_security_events WHERE ctid = ANY (ARRAY(SELECT ctid FROM host_security_events WHERE event_time < now() - make_interval(days => $1::int) LIMIT $2))`,
	},
	"host_enforcement_events": {
		oldest:      `SELECT min(event_time) FROM host_enforcement_events`,
		deleteBatch: `DELETE FROM host_enforcement_events WHERE ctid = ANY (ARRAY(SELECT ctid FROM host_enforcement_events WHERE event_time < now() - make_interval(days => $1::int) LIMIT $2))`,
	},
	"host_fw_features": {
		oldest:      `SELECT min(ts) FROM host_fw_features`,
		deleteBatch: `DELETE FROM host_fw_features WHERE ctid = ANY (ARRAY(SELECT ctid FROM host_fw_features WHERE ts < now() - make_interval(days => $1::int) LIMIT $2))`,
	},
	"host_sec_features": {
		oldest:      `SELECT min(ts) FROM host_sec_features`,
		deleteBatch: `DELETE FROM host_sec_features WHERE ctid = ANY (ARRAY(SELECT ctid FROM host_sec_features WHERE ts < now() - make_interval(days => $1::int) LIMIT $2))`,
	},
}

// errUnmanagedTable is returned for a table outside domain.RetentionTables.
var errUnmanagedTable = errors.New("storage: table is not a managed telemetry table")

// checkRetentionDays refuses a retention no table accepts (defence in depth:
// 0 or a negative value would delete every row or every finished chunk).
func checkRetentionDays(days int) error {
	if days < 1 || days > domain.RetentionMaxDays {
		return fmt.Errorf("storage: retention %d days out of range", days)
	}
	return nil
}

// oldestRowTimeout bounds the min() of a plain table (a sequential scan on a
// large table without TimescaleDB): past it the oldest row is unknown.
const oldestRowTimeout = "3s"

// Statement timeouts of the retention work (constants, never input).
const (
	dropChunksTimeout  = "10min"
	deleteBatchTimeout = "2min"
)

// retentionLockKey is the advisory lock of the control-plane retention job.
const retentionLockKey int64 = 0x7761_6669_6f72_6574 // "wafioret"

// TimescaleInfo reads the TimescaleDB extension version and license.
func (r *StorageRepo) TimescaleInfo(ctx context.Context) (domain.TimescaleInfo, error) {
	var info domain.TimescaleInfo
	var ver *string
	err := r.pool.QueryRow(ctx, `SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'`).Scan(&ver)
	if errors.Is(err, pgx.ErrNoRows) {
		return info, nil
	}
	if err != nil {
		return info, err
	}
	if ver == nil {
		return info, nil
	}
	info.Installed, info.Version = true, *ver
	var lic *string
	if err := r.pool.QueryRow(ctx, `SELECT current_setting('timescaledb.license', true)`).Scan(&lic); err != nil {
		return info, err
	}
	if lic != nil {
		info.License = *lic
	}
	return info, nil
}

// TableStats reads the size, chunks, compression and retention policy of a
// managed table. A table that does not exist reports Exists false.
func (r *StorageRepo) TableStats(ctx context.Context, t domain.RetentionTable, withOldestRow bool) (domain.TableStorageStats, error) {
	var st domain.TableStorageStats
	stmts, ok := plainTableSQL[t.Name]
	if !ok {
		return st, errUnmanagedTable
	}
	var exists bool
	if err := r.pool.QueryRow(ctx,
		`SELECT to_regclass(quote_ident(current_schema()) || '.' || quote_ident($1)) IS NOT NULL`, t.Name,
	).Scan(&exists); err != nil {
		return st, err
	}
	if !exists {
		return st, nil
	}
	st.Exists = true

	var hasTS bool
	if err := r.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')`).Scan(&hasTS); err != nil {
		return st, err
	}
	if hasTS {
		err := r.pool.QueryRow(ctx,
			`SELECT compression_enabled FROM timescaledb_information.hypertables
			 WHERE hypertable_schema = current_schema() AND hypertable_name = $1`, t.Name,
		).Scan(&st.CompressionEnabled)
		switch {
		case err == nil:
			st.Hypertable = true
		case errors.Is(err, pgx.ErrNoRows):
		default:
			return st, err
		}
	}

	if !st.Hypertable {
		if err := r.pool.QueryRow(ctx, `SELECT pg_total_relation_size($1::text::regclass)`, t.Name).Scan(&st.TotalBytes); err != nil {
			return st, err
		}
		if withOldestRow {
			oldest, err := r.oldestRow(ctx, stmts.oldest)
			if err != nil {
				return st, err
			}
			st.OldestRow = oldest
		}
		return st, nil
	}

	if err := r.pool.QueryRow(ctx, `SELECT COALESCE(hypertable_size($1::text::regclass), 0)`, t.Name).Scan(&st.TotalBytes); err != nil {
		return st, err
	}
	chunks, err := r.chunks(ctx, t.Name)
	if err != nil {
		return st, err
	}
	st.Chunks = chunks
	if st.CompressionEnabled {
		if err := r.compression(ctx, t.Name, &st); err != nil {
			return st, err
		}
	}
	pol, err := r.retentionPolicy(ctx, t.Name)
	if err != nil {
		return st, err
	}
	st.Retention = pol
	return st, nil
}

// oldestRow runs a bounded min() in its own transaction (SET LOCAL ends
// with it). A timeout is not an error: the age is then unknown.
func (r *StorageRepo) oldestRow(ctx context.Context, query string) (*time.Time, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout', $1, true)`, oldestRowTimeout); err != nil {
		return nil, err
	}
	var ts pgtype.Timestamptz
	if err := tx.QueryRow(ctx, query).Scan(&ts); err != nil {
		if isQueryCanceled(err) {
			return nil, nil
		}
		return nil, err
	}
	return finiteTime(ts), nil
}

func (r *StorageRepo) chunks(ctx context.Context, table string) ([]domain.StorageChunk, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT c.range_start, c.range_end, c.is_compressed, COALESCE(s.total_bytes, 0)
		 FROM timescaledb_information.chunks c
		 LEFT JOIN chunks_detailed_size($1::text::regclass) s
		   ON s.chunk_schema = c.chunk_schema AND s.chunk_name = c.chunk_name
		 WHERE c.hypertable_schema = current_schema() AND c.hypertable_name = $1
		 ORDER BY c.range_start`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.StorageChunk
	for rows.Next() {
		var start, end pgtype.Timestamptz
		var c domain.StorageChunk
		if err := rows.Scan(&start, &end, &c.Compressed, &c.Bytes); err != nil {
			return nil, err
		}
		s, e := finiteTime(start), finiteTime(end)
		if s == nil || e == nil {
			continue
		}
		c.Start, c.End = *s, *e
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *StorageRepo) compression(ctx context.Context, table string, st *domain.TableStorageStats) error {
	var compressed *int64
	var before, after *int64
	err := r.pool.QueryRow(ctx,
		`SELECT number_compressed_chunks::bigint, before_compression_total_bytes, after_compression_total_bytes
		 FROM hypertable_compression_stats($1::text::regclass)`, table,
	).Scan(&compressed, &before, &after)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if compressed != nil {
		st.CompressedChunks = int(*compressed)
	}
	if before != nil {
		st.BeforeBytes = *before
	}
	if after != nil {
		st.AfterBytes = *after
	}
	var secs *int64
	err = r.pool.QueryRow(ctx,
		`SELECT EXTRACT(EPOCH FROM (config->>'compress_after')::interval)::bigint
		 FROM timescaledb_information.jobs
		 WHERE proc_name = 'policy_compression' AND hypertable_schema = current_schema() AND hypertable_name = $1
		 ORDER BY job_id LIMIT 1`, table,
	).Scan(&secs)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if secs != nil {
		st.CompressAfter = time.Duration(*secs) * time.Second
	}
	return nil
}

func (r *StorageRepo) retentionPolicy(ctx context.Context, table string) (domain.RetentionPolicy, error) {
	var pol domain.RetentionPolicy
	var secs *int64
	var last pgtype.Timestamptz
	err := r.pool.QueryRow(ctx,
		`SELECT j.job_id, EXTRACT(EPOCH FROM (j.config->>'drop_after')::interval)::bigint, j.scheduled,
		        s.last_successful_finish, COALESCE(s.last_run_status, '')
		 FROM timescaledb_information.jobs j
		 LEFT JOIN timescaledb_information.job_stats s ON s.job_id = j.job_id
		 WHERE j.proc_name = 'policy_retention' AND j.hypertable_schema = current_schema() AND j.hypertable_name = $1
		 ORDER BY j.job_id LIMIT 1`, table,
	).Scan(&pol.JobID, &secs, &pol.Scheduled, &last, &pol.LastStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RetentionPolicy{}, nil
	}
	if err != nil {
		return pol, err
	}
	pol.Exists = true
	if secs != nil {
		pol.DropAfter = time.Duration(*secs) * time.Second
	}
	pol.LastSuccess = finiteTime(last)
	return pol, nil
}

// ApplyRetention replaces each listed hypertable's retention policy
// (remove + add, the TimescaleDB catalog is transactional) and upserts the
// settings row in the same transaction: either every change and the saved
// value land, or none does.
func (r *StorageRepo) ApplyRetention(ctx context.Context, changes []domain.RetentionApply, settingsKey string, settingsValue any) error {
	for _, c := range changes {
		if _, ok := plainTableSQL[c.Table]; !ok {
			return errUnmanagedTable
		}
		if err := checkRetentionDays(c.Days); err != nil {
			return err
		}
	}
	var raw []byte
	if settingsKey != "" {
		var err error
		if raw, err = json.Marshal(settingsValue); err != nil {
			return err
		}
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, c := range changes {
		if _, err := tx.Exec(ctx, `SELECT remove_retention_policy($1::text::regclass, if_exists => true)`, c.Table); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`SELECT add_retention_policy($1::text::regclass, drop_after => make_interval(days => $2::int))`,
			c.Table, c.Days); err != nil {
			return err
		}
	}
	if settingsKey != "" {
		if _, err := tx.Exec(ctx,
			`INSERT INTO system_settings (key, value, updated_at) VALUES ($1, $2, NOW())
			 ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`, settingsKey, raw); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// DropChunksOlderThan drops a hypertable's chunks older than days
// (TimescaleDB resolves the interval against the database clock).
func (r *StorageRepo) DropChunksOlderThan(ctx context.Context, table string, days int) (int, error) {
	if _, ok := plainTableSQL[table]; !ok {
		return 0, errUnmanagedTable
	}
	if err := checkRetentionDays(days); err != nil {
		return 0, err
	}
	// A first drop over many expired chunks can outlast the pool's
	// statement_timeout; it would then roll back and fail the same way
	// every hour.
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout', $1, true)`, dropChunksTimeout); err != nil {
		return 0, err
	}
	var n int
	if err := tx.QueryRow(ctx,
		`SELECT count(*)::int FROM drop_chunks($1::text::regclass, older_than => make_interval(days => $2::int))`,
		table, days).Scan(&n); err != nil {
		return 0, err
	}
	return n, tx.Commit(ctx)
}

// DeleteOlderThan deletes one batch of rows older than days from a plain
// table; the cutoff is now() - days on the database clock, so a
// control-plane clock ahead of the database cannot delete recent rows. Old
// rows sit at the start of an append-only heap, so the ctid subselect stops
// early without an index on the time column.
func (r *StorageRepo) DeleteOlderThan(ctx context.Context, t domain.RetentionTable, days int, limit int) (int64, error) {
	stmts, ok := plainTableSQL[t.Name]
	if !ok {
		return 0, errUnmanagedTable
	}
	if err := checkRetentionDays(days); err != nil {
		return 0, err
	}
	// The last batch of a pass scans the whole table (nothing older left):
	// give it more than the pool's default.
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout', $1, true)`, deleteBatchTimeout); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, stmts.deleteBatch, days, limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), tx.Commit(ctx)
}

// DatabaseSize is the on-disk size of the connected database.
func (r *StorageRepo) DatabaseSize(ctx context.Context) (int64, error) {
	var n int64
	err := r.pool.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&n)
	return n, err
}

// DataDirectory reads data_directory. PostgreSQL shows it only to superusers
// and members of pg_read_all_settings; for any other role pg_settings has no
// row, and "" (no error) is returned. current_setting would raise an error
// instead, written to the server log on every storage check.
func (r *StorageRepo) DataDirectory(ctx context.Context) (string, error) {
	var dir string
	err := r.pool.QueryRow(ctx, `SELECT setting FROM pg_catalog.pg_settings WHERE name = 'data_directory'`).Scan(&dir)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return dir, err
}

// AdminEmails lists the system administrators' addresses (at most 100).
func (r *StorageRepo) AdminEmails(ctx context.Context) ([]string, error) {
	rows, err := r.pool.Query(ctx, `SELECT email FROM users WHERE role = 'admin' ORDER BY email LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// TryRetentionLock takes a session advisory lock on a dedicated connection.
func (r *StorageRepo) TryRetentionLock(ctx context.Context) (func(), bool, error) {
	conn, err := r.pool.Acquire(ctx)
	if err != nil {
		return func() {}, false, err
	}
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, retentionLockKey).Scan(&ok); err != nil {
		conn.Release()
		return func() {}, false, err
	}
	if !ok {
		conn.Release()
		return func() {}, false, nil
	}
	return func() {
		uctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(uctx, `SELECT pg_advisory_unlock($1)`, retentionLockKey); err != nil {
			// The session (and its lock) must not go back to the pool.
			_ = conn.Conn().Close(uctx)
		}
		conn.Release()
	}, true, nil
}

// isQueryCanceled reports a statement_timeout cancellation (SQLSTATE 57014).
func isQueryCanceled(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "57014"
}

// finiteTime returns a finite timestamptz, nil for NULL or ±infinity.
func finiteTime(ts pgtype.Timestamptz) *time.Time {
	if !ts.Valid || ts.InfinityModifier != pgtype.Finite {
		return nil
	}
	t := ts.Time.UTC()
	return &t
}
