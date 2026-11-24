-- Delivery settings of an application, served by the WAF agent itself: the main host name, compression,
-- files from a folder and the response cache, and what the agent reports about them.
--
-- apps.compression      jsonb object {enabled, min_bytes}; {} is off.
-- apps.static_files     jsonb object {enabled, root, missing, max_age_s}; {} is off.
-- apps.cache            jsonb object of the response cache (domain.Cache); {} is off. The three
--                       objects are written by the dashboard through the control plane, which fills
--                       the defaults in and checks every limit; the bundle carries one only while its
--                       enabled is true.
-- apps.tls_canonical_host  the main host name, "" for no redirect. It is one of tls_hosts, and the
--                       agent uses it in gateway mode only. The path prefix lives in proxy_config.
-- agents.edge_redirects, edge_compression, edge_static_files, edge_cache
--                       TRUE  the agent applies that part (Hello features of the same names);
--                       FALSE the agent said Hello without it, so it is older than that part;
--                       NULL  unknown: it never connected, or it is a host agent.
--                       Written on every connect, like tls_certificates (000124).
-- app_edge_status       what the agent last said about one application, replaced as a whole and never
--                       read back into apps: the generation of the bundle it answers, the state of each
--                       part (features, an array), the counters of the last hour and when the server
--                       got it. Shown, never acted on.
-- app_cache_purges      removals of stored copies that the dashboard asked for. id is the command id
--                       the agent acks. A row is pending until the agent that serves the application
--                       acks it (done) or refuses it (failed, with a fixed error code); agent_id and
--                       finished_at say who and when. A purge for an offline agent waits.
--
-- The ALTERs are metadata-only apart from the CHECK constraints, which read a table of a few rows.
-- lock_timeout bounds a wait behind a long reader the same way as 000124 (rerun is safe: IF NOT
-- EXISTS). uq_apps_id_project comes from 000124.
SET lock_timeout = '5s';

ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS compression JSONB NOT NULL DEFAULT '{}'
        CONSTRAINT apps_compression_chk CHECK (jsonb_typeof(compression) = 'object'),
    ADD COLUMN IF NOT EXISTS static_files JSONB NOT NULL DEFAULT '{}'
        CONSTRAINT apps_static_files_chk CHECK (jsonb_typeof(static_files) = 'object'),
    ADD COLUMN IF NOT EXISTS cache JSONB NOT NULL DEFAULT '{}'
        CONSTRAINT apps_cache_chk CHECK (jsonb_typeof(cache) = 'object'),
    ADD COLUMN IF NOT EXISTS tls_canonical_host TEXT NOT NULL DEFAULT ''
        CONSTRAINT apps_tls_canonical_host_chk CHECK (octet_length(tls_canonical_host) <= 253);

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS edge_redirects BOOLEAN,
    ADD COLUMN IF NOT EXISTS edge_compression BOOLEAN,
    ADD COLUMN IF NOT EXISTS edge_static_files BOOLEAN,
    ADD COLUMN IF NOT EXISTS edge_cache BOOLEAN;

CREATE TABLE IF NOT EXISTS app_edge_status (
    app_id      UUID PRIMARY KEY,
    project_id  UUID NOT NULL,
    agent_id    UUID NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    generation  BIGINT NOT NULL CHECK (generation >= 0),
    features    JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(features) = 'array'),
    cache       JSONB CHECK (jsonb_typeof(cache) = 'object'),
    compression JSONB CHECK (jsonb_typeof(compression) = 'object'),
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (app_id, project_id) REFERENCES apps (id, project_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_app_edge_status_agent ON app_edge_status (agent_id);

CREATE TABLE IF NOT EXISTS app_cache_purges (
    id          UUID PRIMARY KEY,
    app_id      UUID NOT NULL,
    project_id  UUID NOT NULL,
    scope       TEXT NOT NULL CHECK (scope IN ('url', 'prefix', 'app')),
    url         TEXT NOT NULL DEFAULT '' CHECK (octet_length(url) <= 2048),
    created_by  UUID NULL REFERENCES users (id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    state       TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'done', 'failed')),
    error       TEXT NOT NULL DEFAULT '' CHECK (octet_length(error) <= 64),
    agent_id    UUID NULL REFERENCES agents (id) ON DELETE SET NULL,
    finished_at TIMESTAMPTZ NULL,
    FOREIGN KEY (app_id, project_id) REFERENCES apps (id, project_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_app_cache_purges_app ON app_cache_purges (app_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_app_cache_purges_pending ON app_cache_purges (app_id) WHERE state = 'pending';

RESET lock_timeout;
