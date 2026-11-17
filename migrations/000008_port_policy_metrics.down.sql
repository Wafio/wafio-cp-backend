ALTER TABLE ebpf_metrics
    DROP COLUMN IF EXISTS port_policy_drops,
    DROP COLUMN IF EXISTS egress_ip_drops;
