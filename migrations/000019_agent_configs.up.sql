-- 000017_agent_configs
-- Per-agent WAF configuration. One row per agent (1 agent = 1 config).
-- Free-tier (mTLS SDK) users continue to use project_configs; self-hosted
-- WAF agents consume this table via the bundle endpoint.

CREATE TABLE IF NOT EXISTS agent_configs (
    agent_id     UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    rules_json   JSONB NOT NULL DEFAULT '{}'::jsonb,
    sensitivity  INT   NOT NULL DEFAULT 2,
    generation   BIGINT NOT NULL DEFAULT 1,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_configs_updated_at
    ON agent_configs(updated_at DESC);
