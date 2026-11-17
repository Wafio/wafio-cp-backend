-- WAF agent heartbeat fields 9 and 10 on the agent row.
--
-- waf_bundle_source     where the WAF config in force came from: 'live' (this
--                       control plane's stream), 'cache' (the agent's
--                       last-bundle.json loaded at start), 'cache_stale' (as
--                       'cache', older than the agent's max cache age), ''
--                       (no bundle applied yet). The server stores any other
--                       value as 'unknown'.
-- waf_bundle_generation generation of the bundle in force (0 = none).
--
-- NULL = the agent predates the fields, or is a host/eBPF agent. Written in
-- the same UPDATE as the 000086/000096/000097 health columns.
--
-- 000098 is reserved for another branch; this migration does not depend on it.
-- Metadata-only ALTER on a small table; lock_timeout bounds a wait behind a
-- long reader the same way as 000096 (rerun is safe: IF NOT EXISTS).
SET lock_timeout = '5s';

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS waf_bundle_source     TEXT,
    ADD COLUMN IF NOT EXISTS waf_bundle_generation BIGINT;

RESET lock_timeout;
