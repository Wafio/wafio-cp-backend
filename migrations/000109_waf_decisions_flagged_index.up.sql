-- False-positive feedback summary (GET /api/projects/:id/waf/feedback/summary):
-- a partial covering index over the flagged
-- decisions (block/log/monitor) of each agent, so the summary's 30-day scan
-- of a project's flagged decisions is an index-only scan instead of a heap
-- read of every flagged row. Partial: allow decisions (the bulk of traffic)
-- are not indexed. Measured on 6M decisions (300k flagged for one project in
-- 30 days, plain PostgreSQL, 128 MB shared_buffers): 3.5 s → 0.17 s for 30d,
-- 0.54 s → 0.07 s for 7d.
--
-- Same two cases as 000089 (TimescaleDB is optional):
--
-- * Plain PostgreSQL: built here. ONE statement on purpose (golang-migrate
--   sends the file as one simple-protocol query = one implicit transaction).
--
-- * TimescaleDB hypertable: this file only emits a NOTICE; `wafio migrate up`
--   (and `serve --migrate`, `migrate fresh`) builds the index one chunk per
--   transaction right after the migrations while the schema version is
--   >= 110 (cmd/wafio/migrate_indexes.go). Other runners run it by hand,
--   off-peak:
--
--   CREATE INDEX IF NOT EXISTS waf_decisions_flagged_agent_recorded_at
--       ON waf_decisions (agent_id, recorded_at DESC)
--       INCLUDE (action, app_id, analyze_method, categories)
--       WITH (timescaledb.transaction_per_chunk)
--       WHERE action IN ('block', 'log', 'monitor');
DO $fpsum$
DECLARE
    is_hypertable boolean := false;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        SELECT EXISTS (
            SELECT 1 FROM timescaledb_information.hypertables
             WHERE hypertable_name = 'waf_decisions'
               AND hypertable_schema = current_schema())
          INTO is_hypertable;
    END IF;
    IF is_hypertable THEN
        RAISE NOTICE 'waf_decisions is a hypertable: index waf_decisions_flagged_agent_recorded_at is built per chunk after the migrations (wafio migrate up)';
    ELSE
        CREATE INDEX IF NOT EXISTS waf_decisions_flagged_agent_recorded_at
            ON waf_decisions (agent_id, recorded_at DESC)
            INCLUDE (action, app_id, analyze_method, categories)
            WHERE action IN ('block', 'log', 'monitor');
    END IF;
END
$fpsum$;
