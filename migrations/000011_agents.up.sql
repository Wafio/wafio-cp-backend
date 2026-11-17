-- Generalize ebpf_agents into a kind-tagged agents table, keeping ebpf_agents
-- as a backward-compat view for 1 release.
--
-- Existing rows are treated as kind='ebpf'. New kind='waf' rows serve HTTP
-- traffic and can be assigned to multiple apps via waf_agent_apps (000012).

-- ── 1. Rename base table ───────────────────────────────────────────────────
ALTER TABLE IF EXISTS ebpf_agents RENAME TO agents;

-- ── 2. Add new columns ─────────────────────────────────────────────────────
ALTER TABLE agents ADD COLUMN IF NOT EXISTS kind       VARCHAR(16) NOT NULL DEFAULT 'ebpf';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS hostname   VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS version    VARCHAR(64)  NOT NULL DEFAULT '';

ALTER TABLE agents
    ADD CONSTRAINT agents_kind_check CHECK (kind IN ('ebpf','waf'));

CREATE INDEX IF NOT EXISTS idx_agents_kind       ON agents(kind);
CREATE INDEX IF NOT EXISTS idx_agents_user_kind  ON agents(user_id, kind);

-- ── 3. Rename old agent-scoped indexes (non-destructive — only if exist) ───
ALTER INDEX IF EXISTS idx_ebpf_agents_user    RENAME TO idx_agents_user;
ALTER INDEX IF EXISTS idx_ebpf_agents_project RENAME TO idx_agents_project;

-- ── 4. Compat view so existing handlers keep working during rollout ────────
-- Only the kind='ebpf' rows are exposed through the legacy name.
CREATE OR REPLACE VIEW ebpf_agents AS
    SELECT id, user_id, name, api_key_hash, last_seen, created_at,
           project_id, callback_url
    FROM agents
    WHERE kind = 'ebpf';
