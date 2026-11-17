-- Revert: drop compat view, drop kind/hostname/version, rename back.

DROP VIEW IF EXISTS ebpf_agents;

ALTER INDEX IF EXISTS idx_agents_project RENAME TO idx_ebpf_agents_project;
ALTER INDEX IF EXISTS idx_agents_user    RENAME TO idx_ebpf_agents_user;

DROP INDEX IF EXISTS idx_agents_user_kind;
DROP INDEX IF EXISTS idx_agents_kind;

ALTER TABLE IF EXISTS agents DROP CONSTRAINT IF EXISTS agents_kind_check;
ALTER TABLE IF EXISTS agents DROP COLUMN IF EXISTS version;
ALTER TABLE IF EXISTS agents DROP COLUMN IF EXISTS hostname;
ALTER TABLE IF EXISTS agents DROP COLUMN IF EXISTS kind;

ALTER TABLE IF EXISTS agents RENAME TO ebpf_agents;
