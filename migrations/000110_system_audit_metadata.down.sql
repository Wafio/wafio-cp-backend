-- Same lock_timeout rationale as the up migration. The details recorded
-- since 000110 are lost; the audit rows themselves stay.
SET lock_timeout = '5s';

ALTER TABLE system_audit
    DROP COLUMN IF EXISTS metadata;

RESET lock_timeout;
