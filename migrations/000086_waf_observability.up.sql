-- WAF inspection-health observability.
--
-- Both ALTERs take ACCESS EXCLUSIVE (on waf_decisions: the hypertable and
-- every chunk). They are metadata-only and fast, but while one WAITS for a
-- conflicting lock (a long dashboard or retention query) every later decision
-- COPY and agent heartbeat queues behind it. lock_timeout bounds that stall:
-- if the lock is not granted within 5s the whole file rolls back (it runs as
-- one implicit transaction) and golang-migrate marks version 86 dirty. Recover
-- per docs/migration-rollout.md §2a and rerun during low traffic; every
-- statement here is IF NOT EXISTS, so a rerun is safe.
SET lock_timeout = '5s';

-- agents: latest inspection-health counters reported on the WAF agent
-- heartbeat. Cumulative since the agent process started (they reset on
-- restart). NULL = the agent never reported them (pre-v1.2 agent, or a
-- host/eBPF agent), which the dashboard shows as "not reported" rather than
-- a healthy zero.
ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS analyze_panics_total         BIGINT,
    ADD COLUMN IF NOT EXISTS engine_panics_total          BIGINT,
    ADD COLUMN IF NOT EXISTS partial_coverage_total       BIGINT,
    ADD COLUMN IF NOT EXISTS parse_budget_exhausted_total BIGINT,
    ADD COLUMN IF NOT EXISTS waf_health_updated_at        TIMESTAMPTZ;

-- waf_decisions: semantic-scan coverage flags per decision ("field_cap,
-- body_binary", ...). NULL/empty = complete coverage or a pre-v1.2 agent.
-- Nullable, no default: a metadata-only ALTER on the hypertable (no chunk
-- rewrite), and waf_decisions has no compression policy.
ALTER TABLE waf_decisions ADD COLUMN IF NOT EXISTS coverage TEXT;

RESET lock_timeout;
