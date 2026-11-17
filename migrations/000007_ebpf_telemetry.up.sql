-- eBPF telemetry ingestion: agent pushes data to server, persisted in PostgreSQL.
-- Supports multi-agent topology. Each agent registers via HMAC-signed API key.

-- ── Agent Registry ──────────────────────────────────────────────────────────
-- Each agent has a unique API key for push authentication.
CREATE TABLE IF NOT EXISTS ebpf_agents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        VARCHAR(255) NOT NULL,
    api_key_hash VARCHAR(128) NOT NULL UNIQUE,   -- bcrypt or sha256 of the agent API key
    last_seen   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_ebpf_agents_user ON ebpf_agents(user_id);

-- ── eBPF Status Snapshots ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ebpf_status (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    UUID NOT NULL REFERENCES ebpf_agents(id) ON DELETE CASCADE,
    payload     JSONB NOT NULL,              -- full status JSON
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_ebpf_status_agent ON ebpf_status(agent_id, recorded_at DESC);

-- ── eBPF Metrics (time-series) ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ebpf_metrics (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        UUID NOT NULL REFERENCES ebpf_agents(id) ON DELETE CASCADE,
    rx_packets      BIGINT NOT NULL DEFAULT 0,
    rx_bytes        BIGINT NOT NULL DEFAULT 0,
    tx_packets      BIGINT NOT NULL DEFAULT 0,
    tx_bytes        BIGINT NOT NULL DEFAULT 0,
    dropped_packets BIGINT NOT NULL DEFAULT 0,
    dropped_bytes   BIGINT NOT NULL DEFAULT 0,
    ratelimited_packets BIGINT NOT NULL DEFAULT 0,
    synflood_drops  BIGINT NOT NULL DEFAULT 0,
    blocklist_drops BIGINT NOT NULL DEFAULT 0,
    allowlist_passes BIGINT NOT NULL DEFAULT 0,
    geoblock_drops  BIGINT NOT NULL DEFAULT 0,
    conntrack_entries INT NOT NULL DEFAULT 0,
    port_scan_drops BIGINT NOT NULL DEFAULT 0,
    pps             BIGINT NOT NULL DEFAULT 0,
    bps             BIGINT NOT NULL DEFAULT 0,
    drop_rate_pct   REAL NOT NULL DEFAULT 0,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_ebpf_metrics_agent_time ON ebpf_metrics(agent_id, recorded_at DESC);

-- ── Firewall Events ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ebpf_events (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    UUID NOT NULL REFERENCES ebpf_agents(id) ON DELETE CASCADE,
    src_ip      VARCHAR(45),
    dst_ip      VARCHAR(45),
    src_port    INT,
    dst_port    INT,
    proto       VARCHAR(10),
    action      VARCHAR(20),
    reason      VARCHAR(128),
    tcp_flags   VARCHAR(20),
    pkt_len     INT,
    rule_id     INT,
    event_time  TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_ebpf_events_agent_time ON ebpf_events(agent_id, recorded_at DESC);
CREATE INDEX idx_ebpf_events_action ON ebpf_events(action);

-- ── Connections ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ebpf_connections (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    UUID NOT NULL REFERENCES ebpf_agents(id) ON DELETE CASCADE,
    src_ip      VARCHAR(45),
    dst_ip      VARCHAR(45),
    src_port    INT,
    dst_port    INT,
    proto       VARCHAR(10),
    state       VARCHAR(20),
    first_seen  TIMESTAMPTZ,
    last_seen   TIMESTAMPTZ,
    packets     BIGINT NOT NULL DEFAULT 0,
    bytes       BIGINT NOT NULL DEFAULT 0,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_ebpf_conns_agent ON ebpf_connections(agent_id, recorded_at DESC);

-- ── Bandwidth per IP ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ebpf_bandwidth (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        UUID NOT NULL REFERENCES ebpf_agents(id) ON DELETE CASCADE,
    ip              VARCHAR(45),
    ingress_bytes   BIGINT NOT NULL DEFAULT 0,
    egress_bytes    BIGINT NOT NULL DEFAULT 0,
    ingress_packets BIGINT NOT NULL DEFAULT 0,
    egress_packets  BIGINT NOT NULL DEFAULT 0,
    ingress_bps     BIGINT NOT NULL DEFAULT 0,
    egress_bps      BIGINT NOT NULL DEFAULT 0,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_ebpf_bw_agent ON ebpf_bandwidth(agent_id, recorded_at DESC);

-- ── Trace Events ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ebpf_trace_events (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        UUID NOT NULL REFERENCES ebpf_agents(id) ON DELETE CASCADE,
    pid             INT,
    tid             INT,
    ppid            INT,
    uid             INT,
    gid             INT,
    event_type      INT,
    event_name      VARCHAR(64),
    category        VARCHAR(32),
    severity        INT,
    severity_name   VARCHAR(16),
    comm            VARCHAR(64),
    filename        TEXT,
    args            TEXT,
    flags           BIGINT,
    ret_val         INT,
    detail          BIGINT,
    port            INT,
    addr_family     INT,
    addr            VARCHAR(64),
    description     TEXT,
    action          INT,
    action_name     VARCHAR(16),
    policy_id       INT,
    event_time      TIMESTAMPTZ NOT NULL,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_trace_events_agent_time ON ebpf_trace_events(agent_id, recorded_at DESC);
CREATE INDEX idx_trace_events_severity ON ebpf_trace_events(severity);
CREATE INDEX idx_trace_events_category ON ebpf_trace_events(category);

-- ── Trace Stats Snapshots ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ebpf_trace_stats (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    UUID NOT NULL REFERENCES ebpf_agents(id) ON DELETE CASCADE,
    payload     JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_trace_stats_agent ON ebpf_trace_stats(agent_id, recorded_at DESC);

-- ── Enforcement Log ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ebpf_enforcement_log (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    UUID NOT NULL REFERENCES ebpf_agents(id) ON DELETE CASCADE,
    policy_id   INT,
    policy_name VARCHAR(255),
    action      VARCHAR(32),
    success     BOOLEAN NOT NULL DEFAULT false,
    event_data  JSONB,
    event_time  TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_enforcement_agent_time ON ebpf_enforcement_log(agent_id, recorded_at DESC);

-- ── Data Retention: auto-cleanup old telemetry ──────────────────────────────
-- Recommended: run via pg_cron or external cron every hour:
--   DELETE FROM ebpf_metrics WHERE recorded_at < NOW() - INTERVAL '7 days';
--   DELETE FROM ebpf_events WHERE recorded_at < NOW() - INTERVAL '3 days';
--   DELETE FROM ebpf_trace_events WHERE recorded_at < NOW() - INTERVAL '3 days';
--   DELETE FROM ebpf_connections WHERE recorded_at < NOW() - INTERVAL '1 day';
--   DELETE FROM ebpf_bandwidth WHERE recorded_at < NOW() - INTERVAL '1 day';
--   DELETE FROM ebpf_enforcement_log WHERE recorded_at < NOW() - INTERVAL '30 days';
--   DELETE FROM ebpf_status WHERE recorded_at < NOW() - INTERVAL '1 day';
--   DELETE FROM ebpf_trace_stats WHERE recorded_at < NOW() - INTERVAL '7 days';
