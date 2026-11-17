-- api_key_hash is legacy. Since host-key + mTLS credential auth took over
-- (000014), the column only ever held random placeholders to satisfy an old
-- UNIQUE constraint. No code reads it; the ebpf_agents compatibility view is
-- recreated without it so the fake data stops being exposed at all.

DROP VIEW IF EXISTS ebpf_agents;
ALTER TABLE agents DROP COLUMN IF EXISTS api_key_hash;
CREATE VIEW ebpf_agents AS
    SELECT id, user_id, name, last_seen, created_at, project_id, host_id, host_info, host_os, host_os_version, host_kernel, host_arch, host_cpu_count, host_memory, host_virt, host_boot_time, host_updated_at, proxy_listen_port, desired_state, last_status_json, last_metrics_json, last_trace_stats_json, last_state_at, last_connections_json, last_bandwidth_json
    FROM agents
    WHERE kind = 'ebpf';
