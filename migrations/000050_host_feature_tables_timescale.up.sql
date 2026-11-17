-- Migration 000050: host_fw_features and host_sec_features as TimescaleDB hypertables.
-- Pre-aggregated feature tables — flushed every 30s by the feature extractor.
-- Replaces GROUP BY queries on raw Manticore event tables.

-- Firewall feature store: ~2,880 rows/day/agent vs 8.6M raw events.
CREATE TABLE IF NOT EXISTS host_fw_features (
    id           bigserial,
    agent_id     text        NOT NULL,
    ts           timestamptz NOT NULL,
    drop_count   bigint      NOT NULL DEFAULT 0,
    allow_count  bigint      NOT NULL DEFAULT 0,
    unique_src   bigint      NOT NULL DEFAULT 0,
    peak_hour    int         NOT NULL DEFAULT 0,
    r_blocklist  bigint      NOT NULL DEFAULT 0,
    r_syn_flood  bigint      NOT NULL DEFAULT 0,
    r_rate_limit bigint      NOT NULL DEFAULT 0,
    r_geo_block  bigint      NOT NULL DEFAULT 0,
    r_port_scan  bigint      NOT NULL DEFAULT 0,
    r_port_policy bigint     NOT NULL DEFAULT 0,
    r_egress     bigint      NOT NULL DEFAULT 0,
    r_other      bigint      NOT NULL DEFAULT 0,
    top_src_ips  text        NOT NULL DEFAULT '[]',
    PRIMARY KEY (id, ts)
);

DO $ts$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM create_hypertable('host_fw_features', 'ts',
        chunk_time_interval => INTERVAL '1 day',
        if_not_exists => TRUE
    );
    END IF;
END
$ts$;

DO $ts$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM add_retention_policy('host_fw_features', INTERVAL '30 days', if_not_exists => TRUE);
    ELSE
        RAISE NOTICE 'timescaledb absent: host_fw_features stays a plain table (no chunking, no automatic retention)';
    END IF;
END
$ts$;

CREATE INDEX IF NOT EXISTS host_fw_features_agent_id_ts
    ON host_fw_features (agent_id, ts DESC);

CREATE INDEX IF NOT EXISTS host_fw_features_peak_hour
    ON host_fw_features (agent_id, peak_hour, ts DESC);

-- Security feature store: ~2,880 rows/day/agent vs 2.6M raw events.
CREATE TABLE IF NOT EXISTS host_sec_features (
    id           bigserial,
    agent_id     text        NOT NULL,
    ts           timestamptz NOT NULL,
    total_events bigint      NOT NULL DEFAULT 0,
    sev_info     bigint      NOT NULL DEFAULT 0,
    sev_low      bigint      NOT NULL DEFAULT 0,
    sev_medium   bigint      NOT NULL DEFAULT 0,
    sev_high     bigint      NOT NULL DEFAULT 0,
    sev_critical bigint      NOT NULL DEFAULT 0,
    cat_counts   jsonb       NOT NULL DEFAULT '{}',
    PRIMARY KEY (id, ts)
);

DO $ts$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM create_hypertable('host_sec_features', 'ts',
        chunk_time_interval => INTERVAL '1 day',
        if_not_exists => TRUE
    );
    END IF;
END
$ts$;

DO $ts$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM add_retention_policy('host_sec_features', INTERVAL '30 days', if_not_exists => TRUE);
    ELSE
        RAISE NOTICE 'timescaledb absent: host_sec_features stays a plain table (no chunking, no automatic retention)';
    END IF;
END
$ts$;

CREATE INDEX IF NOT EXISTS host_sec_features_agent_id_ts
    ON host_sec_features (agent_id, ts DESC);
