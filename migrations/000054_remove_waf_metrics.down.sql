CREATE TABLE IF NOT EXISTS waf_metrics (
    id             BIGSERIAL    PRIMARY KEY,
    agent_id       UUID         NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    app_id         UUID         REFERENCES apps(id) ON DELETE SET NULL,
    window_start   TIMESTAMPTZ  NOT NULL,
    window_seconds INT          NOT NULL DEFAULT 60,
    requests       BIGINT       NOT NULL DEFAULT 0,
    blocks         BIGINT       NOT NULL DEFAULT 0,
    monitor_hits   BIGINT       NOT NULL DEFAULT 0,
    bytes_in       BIGINT       NOT NULL DEFAULT 0,
    bytes_out      BIGINT       NOT NULL DEFAULT 0,
    latency_p50_us INT          NOT NULL DEFAULT 0,
    latency_p95_us INT          NOT NULL DEFAULT 0,
    latency_p99_us INT          NOT NULL DEFAULT 0,
    upstream_errors BIGINT      NOT NULL DEFAULT 0,
    recorded_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_waf_metrics_app_win
    ON waf_metrics(app_id, window_start DESC);
CREATE INDEX IF NOT EXISTS idx_waf_metrics_agent_win
    ON waf_metrics(agent_id, window_start DESC);
