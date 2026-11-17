-- Enforce unique agent name within a project for agents not linked to a host
-- (i.e. WAF/eBPF agents registered directly via the control-plane API).
-- Agents that DO have a host_id are already covered by uq_agents_host_kind_name.
CREATE UNIQUE INDEX IF NOT EXISTS uq_agents_project_name
    ON agents(project_id, name)
    WHERE host_id IS NULL;
