-- Same lock_timeout rationale as the up migration. Every certificate, key and status row goes with
-- the tables; a down migration on a database that serves TLS from the agent turns that off.
SET lock_timeout = '5s';

ALTER TABLE agents
    DROP COLUMN IF EXISTS tls_certificates;

DROP TABLE IF EXISTS app_tls_status;
DROP TABLE IF EXISTS app_certificates;

ALTER TABLE apps
    DROP COLUMN IF EXISTS acme_requested_at,
    DROP COLUMN IF EXISTS acme_request_id,
    DROP COLUMN IF EXISTS tls_certificate_id,
    DROP COLUMN IF EXISTS tls_source,
    DROP COLUMN IF EXISTS tls_redirect_listen,
    DROP COLUMN IF EXISTS tls_listen,
    DROP COLUMN IF EXISTS tls_hosts,
    DROP COLUMN IF EXISTS tls_mode;

DROP INDEX IF EXISTS uq_apps_id_project;

RESET lock_timeout;
