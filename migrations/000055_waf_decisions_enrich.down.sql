ALTER TABLE waf_decisions
    DROP COLUMN IF EXISTS request_headers,
    DROP COLUMN IF EXISTS request_body,
    DROP COLUMN IF EXISTS query_params,
    DROP COLUMN IF EXISTS match_source;
