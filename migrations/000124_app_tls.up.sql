-- TLS served by the WAF agent itself, with a certificate that is uploaded or ordered by the agent.
--
-- apps.tls_mode             'proxy'   TLS is not the agent's business (the default, what every
--                                     application did before);
--                           'gateway' the agent terminates TLS for tls_hosts on tls_listen.
-- apps.tls_hosts            the host names the agent answers for in gateway mode, lower case.
-- apps.tls_listen           ip:port or [ipv6]:port of the HTTPS listener; '' reads as the
--                           default 0.0.0.0:443 until the first save writes it out.
-- apps.tls_redirect_listen  optional plain listener that redirects the hosts to HTTPS; ''= none.
-- apps.tls_source           '' none, 'acme' the agent orders and renews, 'uploaded' the chain
--                           and key in app_certificates.
-- apps.tls_certificate_id   the current uploaded certificate. No foreign key on purpose: a row
--                           of app_certificates is only ever removed with its application, and
--                           every query that follows the pointer also matches the application.
-- apps.acme_request_id      changes when the dashboard asks the agent to order now.
-- apps.acme_requested_at    when it was asked last; limits how often.
--
-- app_certificates          uploaded certificates, one row per upload, never updated in place
--                           except to retire it (replaced_at). chain_pem holds only CERTIFICATE
--                           blocks, re-encoded from the parsed DER. At most one row per
--                           application is current (replaced_at IS NULL). The dashboard is the
--                           only writer.
-- app_certificate_keys      the private key of a certificate, sealed with the AAD of project and
--                           certificate (encb:v1:), in a table of its own so that no query on
--                           app_certificates can return it by accident. Only the delivery to an
--                           agent reads it. A replaced or deleted key is a DELETE of its row. The
--                           ciphertext of a deleted row stays readable in dead tuples until
--                           vacuum, and in the write-ahead log and in backups for as long as
--                           those are kept; it stays sealed, so only changing totp.enc_key and
--                           retiring the old key makes those copies useless.
-- app_tls_status           what the agent last said about the application: one row per
--                           application, replaced as a whole, never read back into apps. The
--                           chain columns describe the certificate in use as the server parsed it
--                           itself; an ACME certificate lives only here, and so does the last
--                           expiry threshold mailed for it (expiry_notified_days, reset when the
--                           leaf changes), because that certificate has no row of its own.
-- agents.tls_certificates   TRUE  the agent serves TLS from the bundle (Hello feature
--                                 'tls_certificates');
--                           FALSE the agent sent features without it;
--                           NULL  unknown: no Hello feature list yet, or a host agent.
--                           Written on every connect, like maintenance_mode (000119).
--
-- uq_apps_id_project exists so that the two new tables can reference (id, project_id) and a row
-- can never carry another project than its application.
--
-- The ALTERs on apps are metadata-only except the unique index and the CHECK constraints, which
-- read a table of a few rows. lock_timeout bounds a wait behind a long reader the same way as
-- 000116 (rerun is safe: IF NOT EXISTS).
SET lock_timeout = '5s';

CREATE UNIQUE INDEX IF NOT EXISTS uq_apps_id_project ON apps (id, project_id);

ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS tls_mode TEXT NOT NULL DEFAULT 'proxy'
        CONSTRAINT apps_tls_mode_chk CHECK (tls_mode IN ('proxy', 'gateway')),
    ADD COLUMN IF NOT EXISTS tls_hosts TEXT[] NOT NULL DEFAULT '{}'
        CONSTRAINT apps_tls_hosts_chk CHECK (cardinality(tls_hosts) <= 100),
    ADD COLUMN IF NOT EXISTS tls_listen TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS tls_redirect_listen TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS tls_source TEXT NOT NULL DEFAULT ''
        CONSTRAINT apps_tls_source_chk CHECK (tls_source IN ('', 'acme', 'uploaded')),
    ADD COLUMN IF NOT EXISTS tls_certificate_id UUID NULL,
    ADD COLUMN IF NOT EXISTS acme_request_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS acme_requested_at TIMESTAMPTZ NULL;

CREATE TABLE IF NOT EXISTS app_certificates (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id           UUID NOT NULL,
    app_id               UUID NOT NULL,
    source               TEXT NOT NULL DEFAULT 'uploaded' CHECK (source = 'uploaded'),
    chain_pem            TEXT NOT NULL,
    leaf_sha256          TEXT NOT NULL CHECK (leaf_sha256 ~ '^[0-9a-f]{64}$'),
    names                TEXT[] NOT NULL DEFAULT '{}',
    issuer               TEXT NOT NULL DEFAULT '',
    key_type             TEXT NOT NULL,
    not_before           TIMESTAMPTZ NOT NULL,
    not_after            TIMESTAMPTZ NOT NULL,
    trusted              BOOLEAN NOT NULL,
    expiry_notified_days INT NULL,
    created_by           UUID NULL REFERENCES users (id) ON DELETE SET NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    replaced_at          TIMESTAMPTZ NULL,
    CONSTRAINT app_certificates_id_project_key UNIQUE (id, project_id),
    FOREIGN KEY (app_id, project_id) REFERENCES apps (id, project_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_app_certificates_app ON app_certificates (app_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_app_certificates_current ON app_certificates (app_id) WHERE replaced_at IS NULL;

-- No CHECK on the ciphertext: Postgres repeats the row in the text of a failed check.
CREATE TABLE IF NOT EXISTS app_certificate_keys (
    certificate_id UUID PRIMARY KEY,
    project_id     UUID NOT NULL,
    key_ciphertext TEXT NOT NULL,
    FOREIGN KEY (certificate_id, project_id) REFERENCES app_certificates (id, project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS app_tls_status (
    app_id          UUID PRIMARY KEY,
    project_id      UUID NOT NULL,
    agent_id        UUID NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    source          TEXT NOT NULL CHECK (source IN ('acme', 'uploaded')),
    state           TEXT NOT NULL CHECK (state IN ('pending', 'active', 'failed', 'missing')),
    certificate_id  UUID NULL REFERENCES app_certificates (id) ON DELETE SET NULL,
    leaf_sha256     TEXT NOT NULL DEFAULT '',
    error           TEXT NOT NULL DEFAULT '' CHECK (octet_length(error) <= 1024),
    next_attempt_at TIMESTAMPTZ NULL,
    request_id      TEXT NOT NULL DEFAULT '',
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    names           TEXT[] NOT NULL DEFAULT '{}',
    issuer          TEXT NOT NULL DEFAULT '',
    not_before      TIMESTAMPTZ NULL,
    not_after       TIMESTAMPTZ NULL,
    chain_pem       TEXT NOT NULL DEFAULT '',
    expiry_notified_days INT NULL,
    FOREIGN KEY (app_id, project_id) REFERENCES apps (id, project_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_app_tls_status_agent ON app_tls_status (agent_id);

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS tls_certificates BOOLEAN;

RESET lock_timeout;
