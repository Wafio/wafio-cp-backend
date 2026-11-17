-- 000013_agent_host_info
-- Store the host info block each agent reports on every push.
-- Columns on the agents table give us fast filters (by OS, kernel, arch)
-- while the full JSON snapshot is kept for UI detail panels.

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS host_info        JSONB,
    ADD COLUMN IF NOT EXISTS host_os          VARCHAR(32),
    ADD COLUMN IF NOT EXISTS host_os_version  VARCHAR(128),
    ADD COLUMN IF NOT EXISTS host_kernel      VARCHAR(128),
    ADD COLUMN IF NOT EXISTS host_arch        VARCHAR(32),
    ADD COLUMN IF NOT EXISTS host_cpu_count   INT,
    ADD COLUMN IF NOT EXISTS host_memory      BIGINT,
    ADD COLUMN IF NOT EXISTS host_virt        VARCHAR(32),
    ADD COLUMN IF NOT EXISTS host_boot_time   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS host_updated_at  TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_agents_host_os   ON agents(host_os)   WHERE host_os   IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_agents_host_virt ON agents(host_virt) WHERE host_virt IS NOT NULL;

-- Refresh the backward-compat view to include the new columns.
DROP VIEW IF EXISTS ebpf_agents;
CREATE VIEW ebpf_agents AS
    SELECT id, user_id, name, api_key_hash, last_seen, created_at,
           project_id, callback_url,
           host_info, host_os, host_os_version, host_kernel, host_arch,
           host_cpu_count, host_memory, host_virt, host_boot_time, host_updated_at
    FROM agents
    WHERE kind = 'ebpf';
