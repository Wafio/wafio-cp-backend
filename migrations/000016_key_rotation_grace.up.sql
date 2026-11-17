-- 000016_key_rotation_grace
-- Allow Host Key and WAF Key rotation without an immediate outage.
--
-- When an operator rotates a key, the *previous* hash+prefix is kept for a
-- short grace window (typically 10 minutes). Agents that still present the
-- old key continue to authenticate during that window; once the grace has
-- expired the old key is rejected and the columns are cleared by a periodic
-- sweeper.
--
-- Columns:
--   prev_host_key_prefix / prev_host_key_hash / prev_host_key_expires_at
--   prev_waf_key_prefix  / prev_waf_key_hash  / prev_waf_key_expires_at
--
-- Prefixes are indexed so the existing short-prefix lookup path can match
-- either the current OR the previous key in a single query.

ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS prev_host_key_prefix     VARCHAR(16),
    ADD COLUMN IF NOT EXISTS prev_host_key_hash       TEXT,
    ADD COLUMN IF NOT EXISTS prev_host_key_expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_hosts_prev_key_prefix
    ON hosts(prev_host_key_prefix)
    WHERE prev_host_key_prefix IS NOT NULL;

ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS prev_waf_key_prefix     VARCHAR(16),
    ADD COLUMN IF NOT EXISTS prev_waf_key_hash       TEXT,
    ADD COLUMN IF NOT EXISTS prev_waf_key_expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_apps_prev_waf_key_prefix
    ON apps(prev_waf_key_prefix)
    WHERE prev_waf_key_prefix IS NOT NULL;
