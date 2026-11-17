-- 000014_hosts
-- Introduce the `hosts` entity: first-class hardware/VM nodes that customer
-- registers from the web UI. Each host holds one eBPF agent (host firewall)
-- and may run N WAF agents. Hosts are only available to Pro/Enterprise tiers;
-- Free tier stays host-less (mTLS SDK).

CREATE TABLE IF NOT EXISTS hosts (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id         UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id            UUID NOT NULL REFERENCES users(id)    ON DELETE CASCADE,

    name               VARCHAR(100) NOT NULL,
    labels             JSONB        NOT NULL DEFAULT '{}',

    -- Host key (single bearer secret used by agents running on this host).
    -- Only the prefix (first 12 chars for UI identification) and the
    -- argon2id hash are persisted; the raw secret is shown once at creation
    -- and never retrievable afterwards.
    host_key_prefix    VARCHAR(16)  NOT NULL,
    host_key_hash      TEXT         NOT NULL,

    status             VARCHAR(16)  NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','online','offline','revoked')),

    -- Last reported host info snapshot (OS, kernel, cpu, mem, etc.).
    -- Duplicated into flat columns for fast filters while the full JSON is
    -- kept for detail views.
    host_info          JSONB,
    host_os            VARCHAR(32),
    host_os_version    VARCHAR(128),
    host_kernel        VARCHAR(128),
    host_arch          VARCHAR(32),
    host_cpu_count     INT,
    host_memory        BIGINT,
    host_virt          VARCHAR(32),
    host_boot_time     TIMESTAMPTZ,

    last_seen          TIMESTAMPTZ,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    revoked_at         TIMESTAMPTZ,

    UNIQUE(project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_hosts_project     ON hosts(project_id);
CREATE INDEX IF NOT EXISTS idx_hosts_user        ON hosts(user_id);
CREATE INDEX IF NOT EXISTS idx_hosts_status      ON hosts(status);
CREATE INDEX IF NOT EXISTS idx_hosts_key_prefix  ON hosts(host_key_prefix);

-- Agents now belong to a host (nullable for now to allow backfill of existing
-- agents registered before the hosts table existed).
ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS host_id UUID REFERENCES hosts(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_agents_host ON agents(host_id);

-- Agents upserted from a Host Key are keyed by (host_id, kind, name).
-- `name` is "host-firewall" for the eBPF agent and the process name
-- (usually the hostname + port) for WAF agents, so multiple WAF agents
-- can coexist on one host.
CREATE UNIQUE INDEX IF NOT EXISTS uq_agents_host_kind_name
    ON agents(host_id, kind, name) WHERE host_id IS NOT NULL;

-- api_key_hash is legacy (SHA-256 of AGENT_API_KEY). Once host-key auth is
-- in place the column is still populated with a random placeholder for
-- schema compatibility; the UNIQUE constraint stays satisfied because the
-- placeholder has enough entropy.

-- Refresh the backward-compat ebpf_agents view to include host_id.
DROP VIEW IF EXISTS ebpf_agents;
CREATE VIEW ebpf_agents AS
    SELECT id, user_id, name, api_key_hash, last_seen, created_at,
           project_id, callback_url, host_id,
           host_info, host_os, host_os_version, host_kernel, host_arch,
           host_cpu_count, host_memory, host_virt, host_boot_time, host_updated_at
    FROM agents
    WHERE kind = 'ebpf';
