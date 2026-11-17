-- 000023_app_configs
-- Per-application WAF configuration. Supplements agent_configs (per-agent)
-- allowing fine-grained rules_json + sensitivity override per application.
-- Fallback chain: app_configs → agent_configs → project_configs.

CREATE TABLE IF NOT EXISTS app_configs (
    app_id      UUID PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
    rules_json  JSONB   NOT NULL DEFAULT '{}'::jsonb,
    sensitivity INT     NOT NULL DEFAULT 2,
    generation  BIGINT  NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_app_configs_updated_at
    ON app_configs(updated_at DESC);
