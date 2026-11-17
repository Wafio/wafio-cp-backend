-- Detection Rules for Runtime Security (Phase 2 — Falco-like rule engine)
-- Rules are evaluated at trace event ingest time. Built-in rules are seeded
-- on project creation and cannot be deleted by users.

CREATE TABLE IF NOT EXISTS trace_detection_rules (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id        UUID        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name              TEXT        NOT NULL,
    description       TEXT        NOT NULL DEFAULT '',
    enabled           BOOLEAN     NOT NULL DEFAULT true,
    built_in          BOOLEAN     NOT NULL DEFAULT false,
    action            TEXT        NOT NULL CHECK (action IN ('suppress','escalate','downgrade','tag')),
    conditions        JSONB       NOT NULL DEFAULT '[]',
    severity_override INT         CHECK (severity_override BETWEEN 0 AND 4),
    priority          INT         NOT NULL DEFAULT 100,
    tags              TEXT[]      NOT NULL DEFAULT '{}',
    hit_count         BIGINT      NOT NULL DEFAULT 0,
    last_hit_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tdr_project_enabled ON trace_detection_rules (project_id) WHERE enabled = true;
CREATE INDEX idx_tdr_project_priority ON trace_detection_rules (project_id, priority);
