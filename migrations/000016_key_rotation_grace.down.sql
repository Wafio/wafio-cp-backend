-- 000016_key_rotation_grace (down)

DROP INDEX IF EXISTS idx_apps_prev_waf_key_prefix;
ALTER TABLE apps
    DROP COLUMN IF EXISTS prev_waf_key_expires_at,
    DROP COLUMN IF EXISTS prev_waf_key_hash,
    DROP COLUMN IF EXISTS prev_waf_key_prefix;

DROP INDEX IF EXISTS idx_hosts_prev_key_prefix;
ALTER TABLE hosts
    DROP COLUMN IF EXISTS prev_host_key_expires_at,
    DROP COLUMN IF EXISTS prev_host_key_hash,
    DROP COLUMN IF EXISTS prev_host_key_prefix;
