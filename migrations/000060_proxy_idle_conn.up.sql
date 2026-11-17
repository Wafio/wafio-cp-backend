-- 000060_proxy_idle_conn
-- Add a per-app upstream idle connection timeout (ms) so operators can align the
-- fasthttp HostClient MaxIdleConnDuration with their upstream's keep-alive timeout.
-- Default 10000 matches the previously hardcoded 10s, so existing routes are unchanged.

ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS proxy_idle_conn_ms INT NOT NULL DEFAULT 10000;
