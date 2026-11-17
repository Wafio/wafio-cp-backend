-- Migration 000112: compress telemetry chunks older than a day (data-model.md,
-- "Kompresi hypertable"). Measured on the demo host's data (2026-10-16):
-- host_security_events 15x smaller, waf_decisions 6x, host_sec_features 7x,
-- host_fw_features 4.6x, host_enforcement_events 3.7x, with every row
-- unchanged (checksums equal before and after); aggregate queries as fast or
-- faster, "latest N" reads into old chunks up to ~2.6x slower (< 260 ms).
--
-- Rows are grouped by agent (every dashboard read filters by agent_id) and
-- ordered newest first. Today's chunk stays uncompressed: inserts, the kill
-- outcome UPDATE on host_security_events (seconds after the event) and the
-- live views never touch compressed data. UPDATE/DELETE on compressed chunks
-- still work (agent delete cascades), only slower.
--
-- Compression needs TimescaleDB 2.11 or later (UPDATE/DELETE on compressed
-- chunks: the kill outcome update, the agent delete cascade) under its
-- community license (timescaledb.license = 'timescale'); a plain PostgreSQL
-- (local development), an older TimescaleDB or an Apache-only build skips it
-- with a notice and keeps the uncompressed tables. The policy job compresses existing old
-- chunks in the background after the migration; the migration itself
-- compresses nothing.
DO $cmp$
DECLARE
    lic text;
    ver text;
    t record;
BEGIN
    SELECT extversion INTO ver FROM pg_extension WHERE extname = 'timescaledb';
    IF ver IS NULL THEN
        RAISE NOTICE '000112: TimescaleDB is not installed; telemetry compression skipped';
        RETURN;
    END IF;
    IF string_to_array(split_part(ver, '-', 1), '.')::int[] < ARRAY[2, 11] THEN
        RAISE NOTICE '000112: TimescaleDB % is older than 2.11 (no UPDATE/DELETE on compressed chunks); telemetry compression skipped', ver;
        RETURN;
    END IF;
    lic := current_setting('timescaledb.license', true);
    IF lic IS DISTINCT FROM 'timescale' THEN
        RAISE NOTICE '000112: TimescaleDB license is % (compression needs the community "timescale" license); telemetry compression skipped', coalesce(lic, 'unknown');
        RETURN;
    END IF;
    FOR t IN
        SELECT * FROM (VALUES
            ('waf_decisions',           'recorded_at'),
            ('host_security_events',    'event_time'),
            ('host_fw_features',        'ts'),
            ('host_sec_features',       'ts'),
            ('host_enforcement_events', 'event_time')
        ) AS v(tbl, timecol)
    LOOP
        CONTINUE WHEN NOT EXISTS (
            SELECT 1 FROM timescaledb_information.hypertables
            WHERE hypertable_schema = current_schema() AND hypertable_name = t.tbl);
        -- Settings an operator already chose are kept (they cannot change
        -- while chunks are compressed).
        IF NOT (SELECT compression_enabled FROM timescaledb_information.hypertables
                WHERE hypertable_schema = current_schema() AND hypertable_name = t.tbl) THEN
            EXECUTE format(
                'ALTER TABLE %I SET (timescaledb.compress, timescaledb.compress_segmentby = %L, timescaledb.compress_orderby = %L)',
                t.tbl, 'agent_id', t.timecol || ' DESC, id DESC');
        END IF;
        PERFORM add_compression_policy(t.tbl::regclass, INTERVAL '1 day', if_not_exists => true);
    END LOOP;
END
$cmp$;
