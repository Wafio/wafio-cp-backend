-- Revert agent host info columns.
DROP VIEW IF EXISTS ebpf_agents;
CREATE VIEW ebpf_agents AS
    SELECT id, user_id, name, api_key_hash, last_seen, created_at,
           project_id, callback_url
    FROM agents
    WHERE kind = 'ebpf';

DROP INDEX IF EXISTS idx_agents_host_os;
DROP INDEX IF EXISTS idx_agents_host_virt;

ALTER TABLE agents
    DROP COLUMN IF EXISTS host_info,
    DROP COLUMN IF EXISTS host_os,
    DROP COLUMN IF EXISTS host_os_version,
    DROP COLUMN IF EXISTS host_kernel,
    DROP COLUMN IF EXISTS host_arch,
    DROP COLUMN IF EXISTS host_cpu_count,
    DROP COLUMN IF EXISTS host_memory,
    DROP COLUMN IF EXISTS host_virt,
    DROP COLUMN IF EXISTS host_boot_time,
    DROP COLUMN IF EXISTS host_updated_at;
