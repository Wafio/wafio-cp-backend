-- WAF agent heartbeat field 20 on the agent row.
--
-- regex_rules_dropped_total = custom GUI/tuning rules the WAF agent dropped at
-- bundle load because their regex was invalid or compiled to more than 256
-- instructions; cumulative since the agent process started (resets on
-- restart). NULL = the agent predates the field, or is a host/eBPF agent.
--
-- Metadata-only ALTER on a small table; lock_timeout bounds a wait behind a
-- long reader the same way as 000096 (rerun is safe: IF NOT EXISTS).
SET lock_timeout = '5s';

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS waf_regex_rules_dropped_total BIGINT;

RESET lock_timeout;
