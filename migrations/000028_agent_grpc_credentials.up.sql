-- 000028_agent_grpc_credentials.up.sql
--
-- Extend mtls_credentials to support the new agent gRPC control plane.
-- Existing credentials default to 'tcp_analyze' (legacy :9089 endpoint).
-- New credentials minted for the WAF agent gRPC stream use 'agent_grpc'.
--
-- Also persist the CA used to sign agent client certs. The CA is created
-- the first time an admin provisions an agent credential and is reused
-- forever after (rotation = mint new client certs from the same CA).

ALTER TABLE mtls_credentials
    ADD COLUMN IF NOT EXISTS purpose VARCHAR(32) NOT NULL DEFAULT 'tcp_analyze';

CREATE INDEX IF NOT EXISTS idx_mtls_credentials_purpose
    ON mtls_credentials(project_id, purpose);

CREATE TABLE IF NOT EXISTS agent_grpc_ca (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- One CA shared across the whole control plane for now. project_id
    -- is kept nullable so we can later partition per-project without a
    -- migration: NULL = global CA, set = per-project CA.
    project_id  UUID NULL REFERENCES projects(id) ON DELETE CASCADE,
    cert_pem    TEXT NOT NULL,
    key_pem     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    not_after   TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_grpc_ca_global
    ON agent_grpc_ca((project_id IS NULL)) WHERE project_id IS NULL;
