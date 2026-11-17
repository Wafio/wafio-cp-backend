-- Same lock_timeout rationale as the up migration.
SET lock_timeout = '5s';

ALTER TABLE agents
    DROP COLUMN IF EXISTS rule_engine;

RESET lock_timeout;
