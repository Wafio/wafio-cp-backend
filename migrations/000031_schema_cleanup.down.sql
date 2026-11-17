-- Reverse migration: restore legacy columns and constraints

-- Restore purpose default
ALTER TABLE mtls_credentials ALTER COLUMN purpose SET DEFAULT 'tcp_analyze';

-- Revert kind constraint
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_kind_check;
UPDATE agents SET kind = 'ebpf' WHERE kind = 'host';
ALTER TABLE agents ADD CONSTRAINT agents_kind_check CHECK (kind IN ('ebpf', 'waf'));

-- Restore removed columns (data is lost). api_key_hash is NOT restored: it was
-- already gone before 000031 (000017 dropped it), so 000031's DROP was a no-op.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS callback_url TEXT NOT NULL DEFAULT '';

-- Recreate the backward-compat view exactly as it stood at 000030.
DROP VIEW IF EXISTS ebpf_agents;
CREATE VIEW ebpf_agents AS
    SELECT id, user_id, name, last_seen, created_at,
           project_id, callback_url, host_id,
           host_info, host_os, host_os_version, host_kernel, host_arch,
           host_cpu_count, host_memory, host_virt, host_boot_time, host_updated_at
    FROM agents
    WHERE kind = 'ebpf';
