-- Migration 000022: rename host_header → listen_host; add listen_port per route.
--
-- The WAF agent now acts as a true inline proxy where each route binds its own
-- TCP listener (listen_host:listen_port) instead of multiplexing on a single
-- port via the incoming Host header. This lets multiple services on the same
-- host be protected by different WAF routes without port conflicts.

-- 1. Rename the routing-key column from host_header to listen_host.
ALTER TABLE apps RENAME COLUMN host_header TO listen_host;

-- 2. Drop the old partial unique index that enforced one Host-header value per
--    project. Routes now differ by port so the old constraint is incorrect.
DROP INDEX IF EXISTS uq_apps_project_host_header;

-- 3. Add a per-route listen port column.
ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS listen_port INTEGER;

ALTER TABLE apps
    ADD CONSTRAINT apps_listen_port_range
    CHECK (listen_port IS NULL OR (listen_port BETWEEN 1 AND 65535));
