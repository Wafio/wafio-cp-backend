-- 000015_apps_waf_keys
-- Shift apps from "mini-PaaS deploy units" into "logical WAF targets".
--
-- Each application now carries a host_header (SNI/Host routing key),
-- an upstream URL (origin the WAF agent proxies to), and its own
-- WAF key (bearer secret used by WAF agents that are authorized to
-- serve that application).
--
-- PaaS-era columns (git_url, fe_*, be_*, db_*, resource limits, container
-- state, deployments) are left in place for one release to avoid breaking
-- existing rows; they will be dropped in a later migration (phase D).

ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS host_header     VARCHAR(255),
    ADD COLUMN IF NOT EXISTS upstream_url    VARCHAR(512),
    ADD COLUMN IF NOT EXISTS waf_key_prefix  VARCHAR(16),
    ADD COLUMN IF NOT EXISTS waf_key_hash    TEXT,
    ADD COLUMN IF NOT EXISTS waf_key_issued_at TIMESTAMPTZ;

-- Soften the formerly-required columns so rows can be created without
-- supplying any PaaS metadata. Deploy-era code paths still read them, but
-- new rows no longer depend on them.
ALTER TABLE apps ALTER COLUMN git_url DROP NOT NULL;

-- Host header uniqueness within a project is required so WAF agents can
-- route via Host: header without ambiguity.
CREATE UNIQUE INDEX IF NOT EXISTS uq_apps_project_host_header
    ON apps(project_id, host_header)
    WHERE host_header IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_apps_waf_key_prefix
    ON apps(waf_key_prefix) WHERE waf_key_prefix IS NOT NULL;

-- Audit log for key/enrollment operations (who generated/rotated/revoked
-- what, from where). Queryable from the UI for enterprise compliance.
CREATE TABLE IF NOT EXISTS agent_audit (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id     UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    actor_user_id  UUID REFERENCES users(id) ON DELETE SET NULL,

    action         VARCHAR(64)  NOT NULL,
    target_type    VARCHAR(32)  NOT NULL,
    target_id      VARCHAR(64),
    target_name    VARCHAR(255),

    ip             INET,
    user_agent     VARCHAR(512),
    metadata       JSONB NOT NULL DEFAULT '{}',

    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_audit_project ON agent_audit(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_audit_action  ON agent_audit(action);
CREATE INDEX IF NOT EXISTS idx_agent_audit_target  ON agent_audit(target_type, target_id);
