-- Reverts 000095. Soft-deleted agents are deleted for real first, and every
-- decision without a live agent with them, so the cascading foreign key can
-- be restored. On a large waf_decisions this delete takes a while; it is what
-- the old per-request cascade did.

DELETE FROM waf_decisions d
 WHERE NOT EXISTS (SELECT 1 FROM agents a WHERE a.id = d.agent_id AND a.deleted_at IS NULL);

DELETE FROM agents WHERE deleted_at IS NOT NULL;

ALTER TABLE waf_decisions DROP CONSTRAINT IF EXISTS waf_decisions_agent_id_fkey;
ALTER TABLE waf_decisions
    ADD CONSTRAINT waf_decisions_agent_id_fkey
    FOREIGN KEY (agent_id) REFERENCES agents (id) ON DELETE CASCADE;

DROP INDEX IF EXISTS uq_agents_host_kind_name;
CREATE UNIQUE INDEX uq_agents_host_kind_name
    ON agents (host_id, kind, name)
    WHERE host_id IS NOT NULL;

DROP INDEX IF EXISTS uq_agents_project_name;
CREATE UNIQUE INDEX uq_agents_project_name
    ON agents (project_id, name)
    WHERE host_id IS NULL;

ALTER TABLE agents DROP COLUMN IF EXISTS deleted_at;
