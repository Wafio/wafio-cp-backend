-- 000108_host_enrollment (UP)
--
-- Host-key enrollment.
-- The installer on a host generates its private key, sends a CSR
-- authenticated by the host key, and the control plane issues a client
-- certificate bound to that host and to one agent (kind + name). Only the
-- certificate and its fingerprint are stored; the key never leaves
-- the host.
--
-- hosts.enroll_expires_at: end of the enrollment window. A host key can
-- enroll only while it is open: Create and RotateKey set it to now + 24 h.
-- Existing hosts keep NULL (closed): keys issued before this migration were
-- handed out as a binding token only and must not start minting
-- certificates; rotating the key opens a window.
ALTER TABLE hosts
    ADD COLUMN IF NOT EXISTS enroll_expires_at TIMESTAMPTZ NULL;

-- (id, project_id) is unique because id is; the index lets credentials
-- reference a host of their own project only (composite FK below).
CREATE UNIQUE INDEX IF NOT EXISTS uq_hosts_id_project ON hosts(id, project_id);

-- mtls_credentials binding. NULL host_id = a project-wide credential made on
-- the Credentials page (unchanged behaviour). A bound credential names its
-- host, the agent kind ('host' | 'waf') and the agent name; Hello accepts it
-- only for that agent on that host. not_after mirrors the certificate's
-- NotAfter so the per-host cap counts active credentials in SQL.
ALTER TABLE mtls_credentials
    ADD COLUMN IF NOT EXISTS host_id    UUID NULL,
    ADD COLUMN IF NOT EXISTS agent_kind VARCHAR(8) NULL,
    ADD COLUMN IF NOT EXISTS agent_name VARCHAR(128) NULL,
    ADD COLUMN IF NOT EXISTS not_after  TIMESTAMPTZ NULL;

ALTER TABLE mtls_credentials
    ADD CONSTRAINT mtls_credentials_host_fk
        FOREIGN KEY (host_id, project_id) REFERENCES hosts(id, project_id) ON DELETE CASCADE;

ALTER TABLE mtls_credentials
    ADD CONSTRAINT mtls_credentials_binding_chk CHECK (
        (host_id IS NULL AND agent_kind IS NULL AND agent_name IS NULL)
        OR (host_id IS NOT NULL AND agent_kind IN ('host', 'waf') AND agent_name IS NOT NULL
            AND length(agent_name) BETWEEN 1 AND 128)
    );

CREATE INDEX IF NOT EXISTS idx_mtls_credentials_host
    ON mtls_credentials(host_id) WHERE host_id IS NOT NULL;

-- One live enrolled credential per agent name in a project, whatever its
-- kind: a renewal deletes the previous credential in the same transaction,
-- the same name cannot be enrolled on two hosts or as both kinds (agents are
-- looked up by name after Hello, so an enrolled name must be unique).
CREATE UNIQUE INDEX IF NOT EXISTS uq_mtls_credentials_agent
    ON mtls_credentials(project_id, agent_name) WHERE host_id IS NOT NULL;
