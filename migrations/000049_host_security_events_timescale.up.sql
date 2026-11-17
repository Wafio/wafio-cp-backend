-- Migration 000049: host_security_events as a TimescaleDB hypertable.
-- Stores sampled runtime security/trace events from host agents.
-- Replaces Manticore host_security_events table.

CREATE TABLE IF NOT EXISTS host_security_events (
    id               bigserial,
    agent_id         text        NOT NULL,
    event_time       timestamptz NOT NULL,
    pid              int         NOT NULL DEFAULT 0,
    tid              int         NOT NULL DEFAULT 0,
    ppid             int         NOT NULL DEFAULT 0,
    uid              int         NOT NULL DEFAULT 0,
    gid              int         NOT NULL DEFAULT 0,
    event_type       int         NOT NULL DEFAULT 0,
    event_name       text        NOT NULL DEFAULT '',
    category         text        NOT NULL DEFAULT '',
    severity         int         NOT NULL DEFAULT 0,
    severity_name    text        NOT NULL DEFAULT '',
    comm             text        NOT NULL DEFAULT '',
    filename         text        NOT NULL DEFAULT '',
    args             text        NOT NULL DEFAULT '',
    flags            bigint      NOT NULL DEFAULT 0,
    ret_val          int         NOT NULL DEFAULT 0,
    detail           bigint      NOT NULL DEFAULT 0,
    port             int         NOT NULL DEFAULT 0,
    addr_family      int         NOT NULL DEFAULT 0,
    addr             text        NOT NULL DEFAULT '',
    description      text        NOT NULL DEFAULT '',
    action           int         NOT NULL DEFAULT 0,
    action_name      text        NOT NULL DEFAULT '',
    policy_id        int         NOT NULL DEFAULT 0,
    parent_comm      text        NOT NULL DEFAULT '',
    grandparent_comm text        NOT NULL DEFAULT '',
    container_id     text        NOT NULL DEFAULT '',
    container_image  text        NOT NULL DEFAULT '',
    container_name   text        NOT NULL DEFAULT '',
    is_container     bool        NOT NULL DEFAULT FALSE,
    is_privileged    bool        NOT NULL DEFAULT FALSE,
    k8s_pod          text        NOT NULL DEFAULT '',
    k8s_namespace    text        NOT NULL DEFAULT '',
    recorded_at      timestamptz NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, event_time)
);

DO $ts$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM create_hypertable('host_security_events', 'event_time',
        chunk_time_interval => INTERVAL '1 day',
        if_not_exists => TRUE
    );
    END IF;
END
$ts$;

-- Prune chunks older than 7 days automatically.
DO $ts$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM add_retention_policy('host_security_events', INTERVAL '7 days', if_not_exists => TRUE);
    ELSE
        RAISE NOTICE 'timescaledb absent: host_security_events stays a plain table (no chunking, no automatic retention)';
    END IF;
END
$ts$;

CREATE INDEX IF NOT EXISTS host_security_events_agent_id_event_time
    ON host_security_events (agent_id, event_time DESC);

CREATE INDEX IF NOT EXISTS host_security_events_category
    ON host_security_events (agent_id, category, event_time DESC);

CREATE INDEX IF NOT EXISTS host_security_events_severity
    ON host_security_events (agent_id, severity, event_time DESC);
