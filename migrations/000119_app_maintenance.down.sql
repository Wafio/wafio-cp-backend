-- Same lock_timeout rationale as the up migration.
SET lock_timeout = '5s';

ALTER TABLE agents
    DROP COLUMN IF EXISTS maintenance_mode;

ALTER TABLE apps
    DROP COLUMN IF EXISTS maintenance;

RESET lock_timeout;
