-- Add live-state JSONB columns to agents for O(1) latest-state lookup.
-- Previously, BatchLatestStatus/Metrics/TraceStats required a full GROUP BY scan
-- on Manticore tables (ebpf_status, host_metrics, ebpf_trace_stats) growing to
-- 259k+ rows/agent/month. These columns replace that with a PK upsert.
ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS last_status_json      JSONB,
    ADD COLUMN IF NOT EXISTS last_metrics_json     JSONB,
    ADD COLUMN IF NOT EXISTS last_trace_stats_json JSONB,
    ADD COLUMN IF NOT EXISTS last_state_at         TIMESTAMPTZ;

-- Composite index for ListAgentsByProject + ListAgentsForUser which both filter
-- by (project_id, kind). Current single-column idx_ebpf_agents_project forces a
-- heap fetch for the kind filter; composite eliminates it.
CREATE INDEX IF NOT EXISTS idx_agents_project_kind ON agents(project_id, kind);
