ALTER TABLE apps DROP CONSTRAINT IF EXISTS apps_listen_port_range;
ALTER TABLE apps DROP COLUMN IF EXISTS listen_port;
ALTER TABLE apps RENAME COLUMN listen_host TO host_header;
CREATE UNIQUE INDEX IF NOT EXISTS uq_apps_project_host_header
    ON apps(project_id, host_header)
    WHERE host_header IS NOT NULL;
