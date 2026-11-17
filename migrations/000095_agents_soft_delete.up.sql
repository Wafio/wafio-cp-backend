-- Agent delete becomes a soft delete.
--
-- Deleting an agent used to DELETE the row, and waf_decisions.agent_id's
-- ON DELETE CASCADE then deleted up to 30 days of that agent's decisions --
-- a hypertable-wide delete -- inside the HTTP request. Now the row is marked
-- deleted_at and its telemetry is left to the 30-day retention policy. Every
-- read of agents filters deleted_at IS NULL, including the tenant joins
-- through agents, so a deleted agent's rows are not visible.
-- Ingest drops decisions of a deleted agent (repository.dropGoneAgentDecisions)
-- in place of the foreign key.
--
-- host_security_events, host_enforcement_events and the host feature tables
-- never had a foreign key to agents; only waf_decisions did.

ALTER TABLE agents ADD COLUMN IF NOT EXISTS deleted_at timestamptz;

-- A deleted agent's name is free again: uniqueness covers live rows only.
-- ON CONFLICT targets in the code name the same predicate.
DROP INDEX IF EXISTS uq_agents_project_name;
CREATE UNIQUE INDEX uq_agents_project_name
    ON agents (project_id, name)
    WHERE host_id IS NULL AND deleted_at IS NULL;

DROP INDEX IF EXISTS uq_agents_host_kind_name;
CREATE UNIQUE INDEX uq_agents_host_kind_name
    ON agents (host_id, kind, name)
    WHERE host_id IS NOT NULL AND deleted_at IS NULL;

-- On a TimescaleDB hypertable the constraint is dropped on every chunk too.
ALTER TABLE waf_decisions DROP CONSTRAINT IF EXISTS waf_decisions_agent_id_fkey;
