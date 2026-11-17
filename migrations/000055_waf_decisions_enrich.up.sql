-- Truncate before enrichment — fresh start.
TRUNCATE TABLE waf_decisions;

-- Add enrichment columns.
ALTER TABLE waf_decisions
    ADD COLUMN IF NOT EXISTS request_headers JSONB,
    ADD COLUMN IF NOT EXISTS request_body    TEXT,
    ADD COLUMN IF NOT EXISTS query_params    TEXT,
    ADD COLUMN IF NOT EXISTS match_source    TEXT;
