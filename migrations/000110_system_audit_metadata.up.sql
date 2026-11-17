-- Details of a system audit event: which settings
-- an administrator changed and their new non-secret values, e.g. the SMTP
-- settings save ({"fields": [...], "host": ..., "password": "changed"}).
-- Never a secret value. NULL = no details (every older row and every event
-- that carries none).
--
-- Metadata-only ALTER (nullable, no default) on a small table; lock_timeout
-- bounds a wait behind a long reader (rerun is safe: IF NOT EXISTS).
SET lock_timeout = '5s';

ALTER TABLE system_audit
    ADD COLUMN IF NOT EXISTS metadata JSONB;

RESET lock_timeout;
