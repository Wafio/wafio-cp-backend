-- Migration 000051: host_enforcement_events as a TimescaleDB hypertable.
-- Stores enforcement log entries (policy actions) from host agents.
-- Replaces Manticore host_enforcement_events table.

CREATE TABLE IF NOT EXISTS host_enforcement_events (
    id                   bigserial,
    agent_id             text        NOT NULL,
    event_time           timestamptz NOT NULL,
    policy_id            int         NOT NULL DEFAULT 0,
    policy_name          text        NOT NULL DEFAULT '',
    action               text        NOT NULL DEFAULT '',
    success              bool        NOT NULL DEFAULT TRUE,
    mode                 text        NOT NULL DEFAULT 'userspace',
    failure_reason       text        NOT NULL DEFAULT '',
    event_data           jsonb,
    mitre_technique_id   text        NOT NULL DEFAULT '',
    mitre_technique_name text        NOT NULL DEFAULT '',
    mitre_tactic         text        NOT NULL DEFAULT '',
    severity             text        NOT NULL DEFAULT '',
    tags                 jsonb       NOT NULL DEFAULT '[]',
    recorded_at          timestamptz NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, event_time)
);

DO $ts$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM create_hypertable('host_enforcement_events', 'event_time',
        chunk_time_interval => INTERVAL '1 day',
        if_not_exists => TRUE
    );
    END IF;
END
$ts$;

DO $ts$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM add_retention_policy('host_enforcement_events', INTERVAL '30 days', if_not_exists => TRUE);
    ELSE
        RAISE NOTICE 'timescaledb absent: host_enforcement_events stays a plain table (no chunking, no automatic retention)';
    END IF;
END
$ts$;

CREATE INDEX IF NOT EXISTS host_enforcement_events_agent_id_event_time
    ON host_enforcement_events (agent_id, event_time DESC);

CREATE INDEX IF NOT EXISTS host_enforcement_events_action
    ON host_enforcement_events (agent_id, action, event_time DESC);
