-- WAF agent heartbeat fields 11-19 on the agent row.
--
-- Latest values reported by the WAF agent heartbeat, next to the 000086
-- inspection-health counters. Counters are cumulative since the agent process
-- started (they reset on restart); script_runs_in_flight is a gauge; the
-- analyze_latency_* values summarise the agent's last 5 minutes (microseconds,
-- percentiles NULL when analyze_latency_samples = 0). NULL everywhere = the
-- agent predates the fields, or is a host/eBPF agent.
--
-- Metadata-only ALTER on a small table; lock_timeout bounds a wait behind a
-- long reader the same way as 000086 (rerun is safe: IF NOT EXISTS).
SET lock_timeout = '5s';

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS script_incomplete_total     BIGINT,
    ADD COLUMN IF NOT EXISTS script_errors_total         BIGINT,
    ADD COLUMN IF NOT EXISTS script_rules_rejected_total BIGINT,
    ADD COLUMN IF NOT EXISTS script_runs_in_flight       BIGINT,
    ADD COLUMN IF NOT EXISTS agent_panics_total          BIGINT,
    ADD COLUMN IF NOT EXISTS analyze_latency_p50_us      BIGINT,
    ADD COLUMN IF NOT EXISTS analyze_latency_p95_us      BIGINT,
    ADD COLUMN IF NOT EXISTS analyze_latency_p99_us      BIGINT,
    ADD COLUMN IF NOT EXISTS analyze_latency_samples     BIGINT;

RESET lock_timeout;
