-- 000034 down: recreate ebpf_metrics exactly as it stood at 000033 (data is
-- not restored; the table had moved to Manticore host_metrics).
CREATE TABLE IF NOT EXISTS ebpf_metrics (
    id                  BIGSERIAL PRIMARY KEY,
    agent_id            UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    rx_packets          bigint DEFAULT 0 NOT NULL,
    rx_bytes            bigint DEFAULT 0 NOT NULL,
    tx_packets          bigint DEFAULT 0 NOT NULL,
    tx_bytes            bigint DEFAULT 0 NOT NULL,
    dropped_packets     bigint DEFAULT 0 NOT NULL,
    dropped_bytes       bigint DEFAULT 0 NOT NULL,
    ratelimited_packets bigint DEFAULT 0 NOT NULL,
    synflood_drops      bigint DEFAULT 0 NOT NULL,
    blocklist_drops     bigint DEFAULT 0 NOT NULL,
    allowlist_passes    bigint DEFAULT 0 NOT NULL,
    geoblock_drops      bigint DEFAULT 0 NOT NULL,
    conntrack_entries   integer DEFAULT 0 NOT NULL,
    port_scan_drops     bigint DEFAULT 0 NOT NULL,
    pps                 bigint DEFAULT 0 NOT NULL,
    bps                 bigint DEFAULT 0 NOT NULL,
    drop_rate_pct       real DEFAULT 0 NOT NULL,
    recorded_at         TIMESTAMPTZ DEFAULT now() NOT NULL,
    port_policy_drops   bigint DEFAULT 0 NOT NULL,
    egress_ip_drops     bigint DEFAULT 0 NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ebpf_metrics_agent_time ON ebpf_metrics (agent_id, recorded_at DESC);
