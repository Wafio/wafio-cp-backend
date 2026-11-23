-- Rollups of waf_decisions for the dashboard: minute counters, the last time each client address was
-- seen, and the largest values of an hour. The control plane fills them (application.WAFRollup); a
-- dashboard read adds the rows they do not cover yet.
--
-- Plain tables with or without TimescaleDB, and waf_decisions is not touched. There is no project_id
-- and no foreign key: a read reaches the project through agents. app_key is the app, or the nil UUID
-- for a decision without one. A bucket is a UTC minute or hour start. No request value sits in an
-- index key: addresses, URIs and user agents are keyed by the md5 of their full text.

-- One row. covered_from is the oldest instant the rollups hold; minute_mark and hour_mark are the
-- first instant the minute rows and the hour rows do not hold yet.
CREATE TABLE IF NOT EXISTS waf_rollup_state (
    id           boolean     PRIMARY KEY DEFAULT true CHECK (id),
    covered_from timestamptz NOT NULL,
    minute_mark  timestamptz NOT NULL,
    hour_mark    timestamptz NOT NULL
);

-- The counters of one minute, with the meaning they have in the summaries and the timelines.
CREATE TABLE IF NOT EXISTS waf_rollup_minute (
    agent_id              uuid        NOT NULL,
    app_key               uuid        NOT NULL,
    bucket                timestamptz NOT NULL,
    requests              int         NOT NULL,
    blocks                int         NOT NULL,
    allows                int         NOT NULL,
    monitors              int         NOT NULL,
    logs                  int         NOT NULL,
    errors                int         NOT NULL,
    challenges            int         NOT NULL,
    semantic              int         NOT NULL,
    other                 int         NOT NULL,
    ws_blocked            int         NOT NULL,
    ws_logged             int         NOT NULL,
    ws_handshake_rejected int         NOT NULL,
    latency_sum           bigint      NOT NULL,
    PRIMARY KEY (agent_id, app_key, bucket)
);

-- The last time each client address ('' included, NULL not) was seen, to count distinct addresses of
-- a window. Its upserts move an indexed column, so no update is a HOT update: vacuum early.
CREATE TABLE IF NOT EXISTS waf_rollup_addr_seen (
    agent_id  uuid        NOT NULL,
    app_key   uuid        NOT NULL,
    addr_key  uuid        NOT NULL,
    last_seen timestamptz NOT NULL,
    PRIMARY KEY (agent_id, app_key, addr_key)
) WITH (autovacuum_vacuum_scale_factor = 0.01, autovacuum_vacuum_insert_scale_factor = 0.01);

CREATE INDEX IF NOT EXISTS waf_rollup_addr_seen_last_seen
    ON waf_rollup_addr_seen (agent_id, app_key, last_seen);

-- Retention deletes by time alone, which the primary key and the index above cannot serve.
CREATE INDEX IF NOT EXISTS waf_rollup_addr_seen_expiry ON waf_rollup_addr_seen (last_seen);

-- The largest values of one agent, app, dimension and hour. dim: 1 uri, 2 user_agent, 3 addr,
-- 4 attack_addr, 5 category, 6 method. key is the md5 of the full value, value is cut to 1024
-- characters. blocks and logs are filled for addr only. The primary key carries the counts, so a
-- list over a month reads the index alone and not the values; vacuum early, so that most of it
-- stays index-only as hours are added.
CREATE TABLE IF NOT EXISTS waf_rollup_hour (
    agent_id uuid        NOT NULL,
    app_key  uuid        NOT NULL,
    dim      smallint    NOT NULL,
    bucket   timestamptz NOT NULL,
    key      uuid        NOT NULL,
    value    text        NOT NULL,
    total    bigint      NOT NULL,
    blocks   bigint      NOT NULL,
    logs     bigint      NOT NULL,
    PRIMARY KEY (agent_id, app_key, dim, bucket, key) INCLUDE (total, blocks, logs)
) WITH (autovacuum_vacuum_insert_scale_factor = 0.01);

-- Retention deletes by time alone, which the primary key cannot serve.
CREATE INDEX IF NOT EXISTS waf_rollup_hour_expiry ON waf_rollup_hour (bucket);
