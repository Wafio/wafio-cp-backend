ALTER TABLE ebpf_trace_policies
    DROP COLUMN IF EXISTS match_dest_ip,
    DROP COLUMN IF EXISTS kill_acknowledged;
