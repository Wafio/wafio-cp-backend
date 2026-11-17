-- 000030_drop_ebpf_log_tables
--
-- High-volume log tables are moved to Manticore Search (same as WAF decisions).
-- PostgreSQL is not the right store for append-only time-series event data.
--
-- Tables being dropped:
--   ebpf_events        → host_firewall_events  (Manticore)
--   ebpf_trace_events  → host_security_events  (Manticore)
--   ebpf_enforcement_log → host_enforcement_events (Manticore)
--
-- Aggregated/config tables (NOT dropped — still in PostgreSQL):
--   ebpf_metrics, ebpf_connections, ebpf_bandwidth, ebpf_status,
--   ebpf_trace_stats, ebpf_trace_policies

DROP TABLE IF EXISTS ebpf_events;
DROP TABLE IF EXISTS ebpf_trace_events;
DROP TABLE IF EXISTS ebpf_enforcement_log;
