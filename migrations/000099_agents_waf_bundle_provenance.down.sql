-- Same lock_timeout rationale as the up migration.
SET lock_timeout = '5s';

ALTER TABLE agents
    DROP COLUMN IF EXISTS waf_bundle_generation,
    DROP COLUMN IF EXISTS waf_bundle_source;

RESET lock_timeout;
