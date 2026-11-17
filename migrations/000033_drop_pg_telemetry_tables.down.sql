-- 000033 down: recreate the telemetry tables exactly as they stood at 000032
-- (reconstructed from applying 000001-000032). Later down migrations
-- (000032, 000025, 000024, ...) alter these tables and fail without them.

CREATE TABLE IF NOT EXISTS waf_decisions (
    id             BIGSERIAL PRIMARY KEY,
    agent_id       UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    app_id         UUID REFERENCES apps(id) ON DELETE SET NULL,
    request_id     VARCHAR(64),
    host           VARCHAR(255) NOT NULL DEFAULT '',
    method         VARCHAR(16),
    uri            TEXT,
    remote_addr    VARCHAR(64),
    user_agent     TEXT,
    action         VARCHAR(16) NOT NULL,
    score          INTEGER NOT NULL DEFAULT 0,
    categories     TEXT[] NOT NULL DEFAULT '{}',
    cwe            VARCHAR(32),
    match_detail   TEXT,
    rule_id        VARCHAR(64),
    body_size      INTEGER NOT NULL DEFAULT 0,
    latency_us     INTEGER NOT NULL DEFAULT 0,
    event_time     TIMESTAMPTZ NOT NULL,
    recorded_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    content_type   VARCHAR(128),
    body_preview   TEXT,
    analyze_method VARCHAR(32)
);
CREATE INDEX IF NOT EXISTS idx_waf_decisions_action ON waf_decisions (action);
CREATE INDEX IF NOT EXISTS idx_waf_decisions_agent_time ON waf_decisions (agent_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_decisions_analyze_method ON waf_decisions (analyze_method) WHERE analyze_method IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_waf_decisions_app_time ON waf_decisions (app_id, recorded_at DESC);

CREATE TABLE IF NOT EXISTS ebpf_status (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    payload     JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ebpf_status_agent ON ebpf_status (agent_id, recorded_at DESC);

CREATE TABLE IF NOT EXISTS ebpf_trace_stats (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    payload     JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_trace_stats_agent ON ebpf_trace_stats (agent_id, recorded_at DESC);

CREATE TABLE IF NOT EXISTS ebpf_connections (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    src_ip      VARCHAR(45),
    dst_ip      VARCHAR(45),
    src_port    INTEGER,
    dst_port    INTEGER,
    proto       VARCHAR(10),
    state       VARCHAR(20),
    first_seen  TIMESTAMPTZ,
    last_seen   TIMESTAMPTZ,
    packets     BIGINT NOT NULL DEFAULT 0,
    bytes       BIGINT NOT NULL DEFAULT 0,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ebpf_conns_agent ON ebpf_connections (agent_id, recorded_at DESC);

CREATE TABLE IF NOT EXISTS ebpf_bandwidth (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    ip              VARCHAR(45),
    ingress_bytes   BIGINT NOT NULL DEFAULT 0,
    egress_bytes    BIGINT NOT NULL DEFAULT 0,
    ingress_packets BIGINT NOT NULL DEFAULT 0,
    egress_packets  BIGINT NOT NULL DEFAULT 0,
    ingress_bps     BIGINT NOT NULL DEFAULT 0,
    egress_bps      BIGINT NOT NULL DEFAULT 0,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ebpf_bw_agent ON ebpf_bandwidth (agent_id, recorded_at DESC);
