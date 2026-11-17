-- Index for the per-app decision feed, summary, timeline and top-N
-- queries (all filter app_id + a recorded_at window). The original
-- idx_waf_decisions_app_time (000012) was lost when 000048 recreated the table.
--
-- Two cases, because TimescaleDB is optional (see 000048):
--
-- * Plain PostgreSQL (waf_decisions is an ordinary table): the index is built
--   here. This file is ONE statement on purpose: golang-migrate sends the
--   whole file as a single simple-protocol query, and a multi-statement query
--   runs as one implicit transaction.
--
-- * TimescaleDB hypertable: a plain CREATE INDEX would build every chunk in
--   one transaction and block decision ingestion (ShareLock on each chunk)
--   for the whole build. The per-chunk form
--   `CREATE INDEX ... WITH (timescaledb.transaction_per_chunk)` cannot run
--   in a transaction block, a DO block or a function (TimescaleDB commits
--   between chunks), and plain PostgreSQL rejects the option, so it cannot
--   live in a migration file that must work on both. This file only emits a
--   NOTICE; `wafio migrate up` (and `serve --migrate`, `migrate fresh`) runs
--   that statement right after the migrations, on its own connection, while
--   the schema version is >= 89 (cmd/wafio/migrate_indexes.go). Operators
--   applying migrations with another runner run it by hand, off-peak:
--
--   CREATE INDEX IF NOT EXISTS waf_decisions_app_id_recorded_at
--       ON waf_decisions (app_id, recorded_at DESC)
--       WITH (timescaledb.transaction_per_chunk);
DO $body$
DECLARE
    is_hypertable boolean := false;
BEGIN
    -- Nested so timescaledb_information is only referenced when the
    -- extension exists (PL/pgSQL plans each statement when it first runs).
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        SELECT EXISTS (
            SELECT 1 FROM timescaledb_information.hypertables
             WHERE hypertable_name = 'waf_decisions'
               AND hypertable_schema = current_schema())
          INTO is_hypertable;
    END IF;
    IF is_hypertable THEN
        RAISE NOTICE 'waf_decisions is a hypertable: index waf_decisions_app_id_recorded_at is built per chunk after the migrations (wafio migrate up)';
    ELSE
        CREATE INDEX IF NOT EXISTS waf_decisions_app_id_recorded_at
            ON waf_decisions (app_id, recorded_at DESC);
    END IF;
END
$body$;
