-- 000030 down: recreate the three log tables exactly as they stood at 000029
-- (data is not restored; Manticore was the source of truth).

CREATE TABLE IF NOT EXISTS ebpf_events (
    id                   BIGSERIAL PRIMARY KEY,
    agent_id             UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    src_ip               VARCHAR(45),
    dst_ip               VARCHAR(45),
    src_port             integer,
    dst_port             integer,
    proto                VARCHAR(10),
    action               VARCHAR(20),
    reason               VARCHAR(128),
    tcp_flags            VARCHAR(20),
    pkt_len              integer,
    rule_id              integer,
    event_time           TIMESTAMPTZ NOT NULL,
    recorded_at          TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ebpf_events_action ON ebpf_events (action);
CREATE INDEX IF NOT EXISTS idx_ebpf_events_agent_time ON ebpf_events (agent_id, recorded_at DESC);

CREATE TABLE IF NOT EXISTS ebpf_trace_events (
    id                   BIGSERIAL PRIMARY KEY,
    agent_id             UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    pid                  integer,
    tid                  integer,
    ppid                 integer,
    uid                  integer,
    gid                  integer,
    event_type           integer,
    event_name           VARCHAR(64),
    category             VARCHAR(32),
    severity             integer,
    severity_name        VARCHAR(16),
    comm                 VARCHAR(64),
    filename             text,
    args                 text,
    flags                bigint,
    ret_val              integer,
    detail               bigint,
    port                 integer,
    addr_family          integer,
    addr                 VARCHAR(64),
    description          text,
    action               integer,
    action_name          VARCHAR(16),
    policy_id            integer,
    event_time           TIMESTAMPTZ NOT NULL,
    recorded_at          TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_trace_events_agent_time ON ebpf_trace_events (agent_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_trace_events_category ON ebpf_trace_events (category);
CREATE INDEX IF NOT EXISTS idx_trace_events_severity ON ebpf_trace_events (severity);

CREATE TABLE IF NOT EXISTS ebpf_enforcement_log (
    id                   BIGSERIAL PRIMARY KEY,
    agent_id             UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    policy_id            integer,
    policy_name          VARCHAR(255),
    action               VARCHAR(32),
    success              boolean DEFAULT false NOT NULL,
    event_data           jsonb,
    event_time           TIMESTAMPTZ NOT NULL,
    recorded_at          TIMESTAMPTZ DEFAULT now() NOT NULL,
    mode                 text DEFAULT 'userspace'::text NOT NULL,
    failure_reason       text DEFAULT ''::text NOT NULL,
    mitre_technique_id   text DEFAULT ''::text NOT NULL,
    mitre_technique_name text DEFAULT ''::text NOT NULL,
    mitre_tactic         text DEFAULT ''::text NOT NULL,
    severity             text DEFAULT ''::text NOT NULL,
    tags                 jsonb DEFAULT '[]'::jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enforcement_agent_time ON ebpf_enforcement_log (agent_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_enforcement_mitre_technique ON ebpf_enforcement_log (mitre_technique_id) WHERE (mitre_technique_id <> ''::text);
CREATE INDEX IF NOT EXISTS idx_enforcement_severity ON ebpf_enforcement_log (severity) WHERE (severity <> ''::text);
CREATE UNIQUE INDEX IF NOT EXISTS uq_enforcement_event ON ebpf_enforcement_log (agent_id, policy_id, event_time);
