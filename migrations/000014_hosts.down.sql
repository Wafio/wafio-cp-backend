-- Roll back hosts introduction.

DROP VIEW IF EXISTS ebpf_agents;

ALTER TABLE agents DROP COLUMN IF EXISTS host_id;

DROP TABLE IF EXISTS hosts;

-- Recreate the previous version of the backward-compat view so downgrade
-- keeps existing handlers working.
CREATE VIEW ebpf_agents AS
    SELECT id, user_id, name, api_key_hash, last_seen, created_at,
           project_id, callback_url,
           host_info, host_os, host_os_version, host_kernel, host_arch,
           host_cpu_count, host_memory, host_virt, host_boot_time, host_updated_at
    FROM agents
    WHERE kind = 'ebpf';
