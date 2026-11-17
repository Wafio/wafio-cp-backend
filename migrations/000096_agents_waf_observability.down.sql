-- Same lock_timeout rationale as the up migration.
SET lock_timeout = '5s';

ALTER TABLE agents
    DROP COLUMN IF EXISTS analyze_latency_samples,
    DROP COLUMN IF EXISTS analyze_latency_p99_us,
    DROP COLUMN IF EXISTS analyze_latency_p95_us,
    DROP COLUMN IF EXISTS analyze_latency_p50_us,
    DROP COLUMN IF EXISTS agent_panics_total,
    DROP COLUMN IF EXISTS script_runs_in_flight,
    DROP COLUMN IF EXISTS script_rules_rejected_total,
    DROP COLUMN IF EXISTS script_errors_total,
    DROP COLUMN IF EXISTS script_incomplete_total;

RESET lock_timeout;
