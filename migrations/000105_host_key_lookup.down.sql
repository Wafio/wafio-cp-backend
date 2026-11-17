-- 000105_host_key_lookup (DOWN)
-- Older code looks host keys up by host_key_prefix only, which every row
-- still carries.
DROP INDEX IF EXISTS idx_hosts_prev_key_lookup;
DROP INDEX IF EXISTS idx_hosts_key_lookup;
ALTER TABLE hosts
    DROP COLUMN IF EXISTS prev_host_key_lookup,
    DROP COLUMN IF EXISTS host_key_lookup;
