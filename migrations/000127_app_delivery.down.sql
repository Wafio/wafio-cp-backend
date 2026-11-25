-- Same lock_timeout rationale as the up migration. The settings, the reports and the purge rows go with
-- the columns and tables; a down migration on a database that serves compression, files or a cache
-- from the agent turns all of that off.
SET lock_timeout = '5s';

DROP TABLE IF EXISTS app_cache_purges;
DROP TABLE IF EXISTS app_edge_status;

ALTER TABLE agents
    DROP COLUMN IF EXISTS edge_cache,
    DROP COLUMN IF EXISTS edge_static_files,
    DROP COLUMN IF EXISTS edge_compression,
    DROP COLUMN IF EXISTS edge_redirects;

ALTER TABLE apps
    DROP COLUMN IF EXISTS tls_canonical_host,
    DROP COLUMN IF EXISTS cache,
    DROP COLUMN IF EXISTS static_files,
    DROP COLUMN IF EXISTS compression;

RESET lock_timeout;
