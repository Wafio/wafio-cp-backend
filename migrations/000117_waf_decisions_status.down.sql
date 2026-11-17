-- Same lock_timeout rationale as the up migration.
SET lock_timeout = '5s';

ALTER TABLE waf_decisions DROP COLUMN IF EXISTS status;

RESET lock_timeout;
