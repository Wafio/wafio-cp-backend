-- status: 'active' = under limit, 'exceeded' = hit limit for this period
ALTER TABLE usage_tcp_requests
ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'active';

COMMENT ON COLUMN usage_tcp_requests.status IS 'active = under limit, exceeded = hit limit for period';
