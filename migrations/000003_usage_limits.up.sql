-- TCP mTLS request usage per entity (project or user) per period (day or month).
-- entity_id = project_id when scope=project, user_id when scope=user.
CREATE TABLE IF NOT EXISTS usage_tcp_requests (
    entity_id   UUID NOT NULL,
    period_start DATE NOT NULL,
    request_count INT NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (entity_id, period_start)
);

CREATE INDEX IF NOT EXISTS idx_usage_tcp_requests_entity_period ON usage_tcp_requests(entity_id, period_start);
