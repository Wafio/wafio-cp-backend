-- Persist Runtime Security (eBPF tracepoint) enforcement policies in the
-- control plane so they survive agent restarts. The agent's PolicyEngine
-- keeps a hot in-memory copy; the server is the source of truth.
--
-- On agent reconnect (next ingest heartbeat after restart), the server
-- detects an empty PolicyEngine via trace_status.policies_total = 0 and
-- replays every stored policy back to the agent's local HTTP API.
CREATE TABLE IF NOT EXISTS ebpf_trace_policies (
    -- Surrogate primary key (server-side identifier, exposed to dashboard).
    id                       UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,

    -- Owning agent. CASCADE so deleting the agent wipes its policies.
    -- ebpf_agents is a view over the agents table; FK references the table.
    agent_id                 UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,

    -- Numeric policy id assigned by the agent's PolicyEngine (uint32).
    -- Unique per agent so we can reconcile DB ↔ agent state on resync.
    -- Nullable because the agent may not have assigned an id yet on the
    -- failure path; the server fills it in once the forward succeeds.
    policy_id                INTEGER,

    name                     VARCHAR(255) NOT NULL,
    description              TEXT NOT NULL DEFAULT '',
    enabled                  BOOLEAN NOT NULL DEFAULT TRUE,

    -- Match criteria — JSONB array of event type names ("execve", ...).
    event_types              JSONB NOT NULL DEFAULT '[]'::jsonb,
    min_severity             VARCHAR(16) NOT NULL DEFAULT 'info',
    match_comm               VARCHAR(255) NOT NULL DEFAULT '',
    match_filename           VARCHAR(512) NOT NULL DEFAULT '',
    match_uid                BIGINT,                   -- nullable = "any uid"
    match_dest_port          VARCHAR(255) NOT NULL DEFAULT '',
    action                   VARCHAR(32)  NOT NULL DEFAULT 'monitor',

    -- Effective and intended kernel-mode flags.
    kernel_enforce           BOOLEAN NOT NULL DEFAULT FALSE,
    kernel_enforce_requested BOOLEAN NOT NULL DEFAULT FALSE,
    auto_downgraded          BOOLEAN NOT NULL DEFAULT FALSE,
    enforcement_mode         VARCHAR(32) NOT NULL DEFAULT 'userspace',

    -- MITRE ATT&CK mapping for SIEM correlation (optional).
    mitre_technique_id       VARCHAR(64) NOT NULL DEFAULT '',
    mitre_technique_name     VARCHAR(255) NOT NULL DEFAULT '',
    mitre_tactic             VARCHAR(64) NOT NULL DEFAULT '',
    severity                 VARCHAR(16) NOT NULL DEFAULT '',
    tags                     JSONB NOT NULL DEFAULT '[]'::jsonb,

    hit_count                BIGINT NOT NULL DEFAULT 0,

    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trace_policies_agent      ON ebpf_trace_policies(agent_id);
CREATE INDEX IF NOT EXISTS idx_trace_policies_agent_pid  ON ebpf_trace_policies(agent_id, policy_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_trace_policies_agent_pid
    ON ebpf_trace_policies(agent_id, policy_id)
    WHERE policy_id IS NOT NULL;
