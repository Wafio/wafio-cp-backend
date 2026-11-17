ALTER TABLE apps
    DROP COLUMN IF EXISTS waf_threshold,
    DROP COLUMN IF EXISTS waf_paranoia,
    DROP COLUMN IF EXISTS waf_body_limit;
