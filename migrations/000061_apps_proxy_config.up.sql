-- 000061_apps_proxy_config
-- Consolidate per-app reverse-proxy tuning into a single JSONB column.
-- Backfills proxy_config from the legacy proxy_* integer columns so existing
-- apps keep identical behavior, then drops the legacy columns and the dead
-- waf_body_limit column (added in 000021, never read).
--
-- trust_forwarded is intentionally omitted from the backfill: the agent treats
-- an absent key as true, matching the current always-trust behavior.

ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS proxy_config jsonb NOT NULL DEFAULT '{}'::jsonb;

UPDATE apps SET proxy_config = jsonb_build_object(
    'max_conns',    COALESCE(proxy_max_conns, 512),
    'conn_wait_ms', COALESCE(proxy_conn_wait_ms, 5000),
    'read_buf',     COALESCE(proxy_read_buf, 16384),
    'write_buf',    COALESCE(proxy_write_buf, 16384),
    'idle_conn_ms', COALESCE(proxy_idle_conn_ms, 10000)
);

ALTER TABLE apps
    DROP COLUMN IF EXISTS proxy_max_conns,
    DROP COLUMN IF EXISTS proxy_conn_wait_ms,
    DROP COLUMN IF EXISTS proxy_read_buf,
    DROP COLUMN IF EXISTS proxy_write_buf,
    DROP COLUMN IF EXISTS proxy_idle_conn_ms,
    DROP COLUMN IF EXISTS waf_body_limit;
