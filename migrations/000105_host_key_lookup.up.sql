-- 000105_host_key_lookup (UP)
--
-- Host key lookup. VerifyKey found the host by host_key_prefix, the
-- 9-character display prefix (wafh_ + 4 base32 characters = 20 bits), which
-- is not unique: with two hosts whose keys share it, VerifyKey read one row
-- and refused the other host's correct key (1,000 hosts: ~34% chance of a
-- collision). host_key_lookup is the first 128 bits of SHA-256 over the whole
-- key (hex), so it names exactly one key; the display prefix is unchanged.
--
-- Rows created before this migration have NULL lookups and are still found
-- by prefix (every candidate is verified); their first successful
-- verification fills the lookup. Rotation moves the current lookup to
-- prev_host_key_lookup like the prefix and hash.
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS host_key_lookup      VARCHAR(32),
    ADD COLUMN IF NOT EXISTS prev_host_key_lookup VARCHAR(32);

-- Unique: a lookup id names one key, so it names one current row.
CREATE UNIQUE INDEX IF NOT EXISTS idx_hosts_key_lookup
    ON hosts(host_key_lookup) WHERE host_key_lookup IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_hosts_prev_key_lookup
    ON hosts(prev_host_key_lookup) WHERE prev_host_key_lookup IS NOT NULL;
