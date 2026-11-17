-- Rollback: re-add the legacy columns, back-fill from proxy_config, drop JSON.
ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS proxy_max_conns    INT NOT NULL DEFAULT 512,
    ADD COLUMN IF NOT EXISTS proxy_conn_wait_ms INT NOT NULL DEFAULT 5000,
    ADD COLUMN IF NOT EXISTS proxy_read_buf     INT NOT NULL DEFAULT 16384,
    ADD COLUMN IF NOT EXISTS proxy_write_buf    INT NOT NULL DEFAULT 16384,
    ADD COLUMN IF NOT EXISTS proxy_idle_conn_ms INT NOT NULL DEFAULT 10000,
    ADD COLUMN IF NOT EXISTS waf_body_limit     INT NOT NULL DEFAULT 1048576;

UPDATE apps SET
    proxy_max_conns    = COALESCE((proxy_config->>'max_conns')::int, 512),
    proxy_conn_wait_ms = COALESCE((proxy_config->>'conn_wait_ms')::int, 5000),
    proxy_read_buf     = COALESCE((proxy_config->>'read_buf')::int, 16384),
    proxy_write_buf    = COALESCE((proxy_config->>'write_buf')::int, 16384),
    proxy_idle_conn_ms = COALESCE((proxy_config->>'idle_conn_ms')::int, 10000);

ALTER TABLE apps DROP COLUMN IF EXISTS proxy_config;
