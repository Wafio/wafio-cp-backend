-- Same lock_timeout rationale as the up migration.
SET lock_timeout = '5s';

ALTER TABLE agents
    DROP COLUMN IF EXISTS waf_regex_rules_dropped_total;

RESET lock_timeout;
