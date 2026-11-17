-- Recreate usage_tcp_requests table (reverse of 000003 + 000004).
CREATE TABLE IF NOT EXISTS usage_tcp_requests (
    entity_id     UUID NOT NULL,
    period_start  DATE NOT NULL,
    request_count INT NOT NULL DEFAULT 0,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status        VARCHAR(20) NOT NULL DEFAULT 'active',
    PRIMARY KEY (entity_id, period_start)
);
CREATE INDEX IF NOT EXISTS idx_usage_tcp_requests_entity_period ON usage_tcp_requests(entity_id, period_start);
COMMENT ON COLUMN usage_tcp_requests.status IS 'active = under limit, exceeded = hit limit for period';
