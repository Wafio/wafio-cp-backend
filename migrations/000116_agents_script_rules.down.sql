-- Same lock_timeout rationale as the up migration.
SET lock_timeout = '5s';

ALTER TABLE agents
    DROP COLUMN IF EXISTS script_rules;

RESET lock_timeout;
