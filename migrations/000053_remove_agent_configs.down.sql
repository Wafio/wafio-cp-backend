CREATE TABLE IF NOT EXISTS agent_configs (
    agent_id   UUID        PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    rules_json JSONB       NOT NULL DEFAULT '{}',
    sensitivity INT        NOT NULL DEFAULT 2,
    generation  BIGINT     NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_configs_updated_at
    ON agent_configs(updated_at DESC);
