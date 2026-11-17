-- Roll back app waf-key columns and the agent audit table.

DROP TABLE IF EXISTS agent_audit;

DROP INDEX IF EXISTS idx_apps_waf_key_prefix;
DROP INDEX IF EXISTS uq_apps_project_host_header;

ALTER TABLE apps
    DROP COLUMN IF EXISTS host_header,
    DROP COLUMN IF EXISTS upstream_url,
    DROP COLUMN IF EXISTS waf_key_prefix,
    DROP COLUMN IF EXISTS waf_key_hash,
    DROP COLUMN IF EXISTS waf_key_issued_at;

ALTER TABLE apps ALTER COLUMN git_url SET NOT NULL;
