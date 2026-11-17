-- Correlation rules: multi-stage attack chains evaluated at trace ingest.
-- Built-ins are seeded per project and cannot be
-- deleted, only disabled — mirroring trace_detection_rules.
CREATE TABLE correlation_rules (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id   UUID NOT NULL,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    enabled      BOOLEAN NOT NULL DEFAULT true,
    built_in     BOOLEAN NOT NULL DEFAULT false,
    entity       TEXT NOT NULL DEFAULT 'process',
    max_span_ms  BIGINT NOT NULL DEFAULT 300000,
    stages       JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, name)
);

CREATE INDEX idx_correlation_rules_project ON correlation_rules (project_id) WHERE enabled = true;
