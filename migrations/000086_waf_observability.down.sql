-- Same lock_timeout rationale as the up migration.
SET lock_timeout = '5s';

ALTER TABLE waf_decisions DROP COLUMN IF EXISTS coverage;

ALTER TABLE agents
    DROP COLUMN IF EXISTS waf_health_updated_at,
    DROP COLUMN IF EXISTS parse_budget_exhausted_total,
    DROP COLUMN IF EXISTS partial_coverage_total,
    DROP COLUMN IF EXISTS engine_panics_total,
    DROP COLUMN IF EXISTS analyze_panics_total;

RESET lock_timeout;
