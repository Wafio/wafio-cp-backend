-- TimescaleDB is optional here, and this migration must not be the thing that
-- stops a database being usable. No migration in this tree ever created the
-- extension, and docker-compose ships plain postgres, so `migrate up` failed at
-- this file and left the database dirty at version 48 -- the documented local
-- setup could not complete. Installing it when available, and degrading loudly
-- when not, keeps hypertables in production without making them a hard
-- requirement for a developer. A plain table holds the same rows; what is lost
-- is chunking and automatic retention, and the notice says so.
DO $tsext$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb') THEN
        EXECUTE 'CREATE EXTENSION IF NOT EXISTS timescaledb';
    END IF;
END
$tsext$;

-- Migration 000048: Recreate waf_decisions as a TimescaleDB hypertable.
-- The table was dropped in migration 000033 (moved to Manticore).
-- Now we bring it back as the primary WAF event store.

CREATE TABLE IF NOT EXISTS waf_decisions (
    id             bigserial,
    agent_id       uuid        NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    app_id         uuid,
    host           text,
    method         text,
    uri            text,
    remote_addr    text,
    country_code   text,
    user_agent     text,
    content_type   text,
    action         text        NOT NULL,
    score          int         NOT NULL DEFAULT 0,
    categories     text[]      NOT NULL DEFAULT '{}',
    cwe            text,
    match_detail   text,
    analyze_method text,
    body_size      int         NOT NULL DEFAULT 0,
    latency_us     int         NOT NULL DEFAULT 0,
    body_preview   text,
    event_time     timestamptz NOT NULL,
    recorded_at    timestamptz NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, recorded_at)
);

DO $ts$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM create_hypertable('waf_decisions'::regclass, 'recorded_at'::name,
        chunk_time_interval => INTERVAL '1 day',
        if_not_exists => TRUE
    );
    END IF;
END
$ts$;

-- Prune chunks older than 30 days automatically.
DO $ts$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM add_retention_policy('waf_decisions', INTERVAL '30 days', if_not_exists => TRUE);
    ELSE
        RAISE NOTICE 'timescaledb absent: waf_decisions stays a plain table (no chunking, no automatic retention)';
    END IF;
END
$ts$;

CREATE INDEX IF NOT EXISTS waf_decisions_agent_id_recorded_at
    ON waf_decisions (agent_id, recorded_at DESC);

CREATE INDEX IF NOT EXISTS waf_decisions_event_time
    ON waf_decisions (event_time DESC);

CREATE INDEX IF NOT EXISTS waf_decisions_action
    ON waf_decisions (action, recorded_at DESC);
