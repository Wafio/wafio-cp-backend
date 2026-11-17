DROP INDEX IF EXISTS idx_agents_project_kind;

ALTER TABLE agents
    DROP COLUMN IF EXISTS last_status_json,
    DROP COLUMN IF EXISTS last_metrics_json,
    DROP COLUMN IF EXISTS last_trace_stats_json,
    DROP COLUMN IF EXISTS last_state_at;
