-- 000108_host_enrollment (DOWN)
--
-- Older code knows no host-bound credential: it would let an enrolled
-- certificate register any agent name of the project. Bound credentials are
-- therefore deleted, not turned into project-wide ones; their agents must be
-- re-provisioned with a project credential after a downgrade.
DELETE FROM mtls_credentials WHERE host_id IS NOT NULL;

DROP INDEX IF EXISTS uq_mtls_credentials_agent;
DROP INDEX IF EXISTS idx_mtls_credentials_host;
ALTER TABLE mtls_credentials DROP CONSTRAINT IF EXISTS mtls_credentials_binding_chk;
ALTER TABLE mtls_credentials DROP CONSTRAINT IF EXISTS mtls_credentials_host_fk;
ALTER TABLE mtls_credentials
    DROP COLUMN IF EXISTS not_after,
    DROP COLUMN IF EXISTS agent_name,
    DROP COLUMN IF EXISTS agent_kind,
    DROP COLUMN IF EXISTS host_id;

DROP INDEX IF EXISTS uq_hosts_id_project;
ALTER TABLE hosts DROP COLUMN IF EXISTS enroll_expires_at;
