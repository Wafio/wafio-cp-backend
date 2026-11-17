-- 000063_host_incidents
-- Persistent triage layer over runtime-security telemetry. One ACTIVE incident
-- per (project, host, MITRE technique, process); critical/high events upsert it.
CREATE TABLE IF NOT EXISTS host_incidents (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id         uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    agent_id           text NOT NULL,
    technique_id       text NOT NULL DEFAULT '',
    tactic             text NOT NULL DEFAULT '',
    comm               text NOT NULL DEFAULT '',
    severity           smallint NOT NULL,
    severity_name      text NOT NULL,
    status             text NOT NULL DEFAULT 'open',
    event_count        bigint NOT NULL DEFAULT 1,
    first_seen_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at       timestamptz NOT NULL DEFAULT now(),
    acknowledged_at    timestamptz,
    acknowledged_by    text,
    resolved_at        timestamptz,
    resolved_by        text,
    sample_description text NOT NULL DEFAULT '',
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS host_incidents_active_key
    ON host_incidents (project_id, agent_id, technique_id, comm)
    WHERE status <> 'resolved';

CREATE INDEX IF NOT EXISTS host_incidents_project_status_seen
    ON host_incidents (project_id, status, last_seen_at DESC);
