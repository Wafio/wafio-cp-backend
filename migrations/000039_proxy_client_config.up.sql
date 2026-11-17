-- 000039_proxy_client_config
-- Add per-app upstream proxy client tuning columns so operators can
-- configure the fasthttp HostClient behaviour from the WAF Agent UI.
--
-- Defaults match the previously hardcoded fasthttp values, so existing
-- routes keep their behaviour until an operator explicitly changes them.

ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS proxy_max_conns    INT NOT NULL DEFAULT 512,
    ADD COLUMN IF NOT EXISTS proxy_conn_wait_ms INT NOT NULL DEFAULT 5000,
    ADD COLUMN IF NOT EXISTS proxy_read_buf     INT NOT NULL DEFAULT 16384,
    ADD COLUMN IF NOT EXISTS proxy_write_buf    INT NOT NULL DEFAULT 16384;
