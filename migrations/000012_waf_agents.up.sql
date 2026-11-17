-- WAF agent fleet: assignment to apps, per-request decisions, aggregated metrics.
--
-- One WAF agent serves many apps. Each app is routed by Host header inside the
-- agent. The server is the source of truth for the assignment; agents pull a
-- "bundle" (see /v1/waf/bundle) describing which apps they currently serve.

-- ── 1. waf_agent_apps ──────────────────────────────────────────────────────
-- Links a kind='waf' agent to an app. Only one enabled row per app at a time.
CREATE TABLE IF NOT EXISTS waf_agent_apps (
    agent_id   UUID    NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    app_id     UUID    NOT NULL REFERENCES apps(id)   ON DELETE CASCADE,
    priority   INT     NOT NULL DEFAULT 100,
    enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    mode       VARCHAR(16) NOT NULL DEFAULT 'block', -- 'block' | 'monitor'
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(agent_id, app_id),
    CONSTRAINT waf_agent_apps_mode_check CHECK (mode IN ('block','monitor'))
);

CREATE INDEX IF NOT EXISTS idx_waf_agent_apps_app   ON waf_agent_apps(app_id);
CREATE INDEX IF NOT EXISTS idx_waf_agent_apps_agent ON waf_agent_apps(agent_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_waf_agent_apps_enabled
    ON waf_agent_apps(app_id) WHERE enabled;

-- ── 2. waf_decisions — per-request verdicts (sampled) ──────────────────────
CREATE TABLE IF NOT EXISTS waf_decisions (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    app_id      UUID         REFERENCES apps(id)   ON DELETE SET NULL,
    request_id  VARCHAR(64),
    host        VARCHAR(255) NOT NULL DEFAULT '',
    method      VARCHAR(16),
    uri         TEXT,
    remote_addr VARCHAR(64),
    user_agent  TEXT,
    action      VARCHAR(16) NOT NULL,          -- 'block' | 'allow' | 'monitor'
    score       INT NOT NULL DEFAULT 0,
    categories  TEXT[] NOT NULL DEFAULT '{}',
    cwe         VARCHAR(32),
    match_detail TEXT,
    rule_id     VARCHAR(64),
    body_size   INT NOT NULL DEFAULT 0,
    latency_us  INT NOT NULL DEFAULT 0,
    event_time  TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_waf_decisions_app_time
    ON waf_decisions(app_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_decisions_agent_time
    ON waf_decisions(agent_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_decisions_action
    ON waf_decisions(action);

-- ── 3. waf_metrics — per-app, per-minute aggregates ───────────────────────
CREATE TABLE IF NOT EXISTS waf_metrics (
    id             BIGSERIAL PRIMARY KEY,
    agent_id       UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    app_id         UUID         REFERENCES apps(id)   ON DELETE SET NULL,
    window_start   TIMESTAMPTZ NOT NULL,
    window_seconds INT NOT NULL DEFAULT 60,
    requests       BIGINT NOT NULL DEFAULT 0,
    blocks         BIGINT NOT NULL DEFAULT 0,
    monitor_hits   BIGINT NOT NULL DEFAULT 0,
    bytes_in       BIGINT NOT NULL DEFAULT 0,
    bytes_out      BIGINT NOT NULL DEFAULT 0,
    latency_p50_us INT NOT NULL DEFAULT 0,
    latency_p95_us INT NOT NULL DEFAULT 0,
    latency_p99_us INT NOT NULL DEFAULT 0,
    upstream_errors BIGINT NOT NULL DEFAULT 0,
    recorded_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_waf_metrics_app_win
    ON waf_metrics(app_id, window_start DESC);
CREATE INDEX IF NOT EXISTS idx_waf_metrics_agent_win
    ON waf_metrics(agent_id, window_start DESC);

-- ── 4. Bundle generation counter per waf agent ─────────────────────────────
-- Agent pulls GET /v1/waf/bundle with If-None-Match: "<generation>". Server
-- bumps the generation for an agent whenever assignment or app config changes.
CREATE TABLE IF NOT EXISTS waf_agent_bundles (
    agent_id    UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    generation  BIGINT NOT NULL DEFAULT 1,
    last_pulled TIMESTAMPTZ,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
