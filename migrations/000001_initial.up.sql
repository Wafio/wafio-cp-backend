-- Users (for register/login)
CREATE TABLE IF NOT EXISTS users (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email      VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    name       VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);

-- Projects (per user)
CREATE TABLE IF NOT EXISTS projects (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        VARCHAR(255) NOT NULL,
    code        VARCHAR(64) NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, code)
);

CREATE INDEX idx_projects_user_id ON projects(user_id);
CREATE INDEX idx_projects_code ON projects(code);

-- Per-project WAF config (JSON: thresholds, block_policy, categories like rules.json)
CREATE TABLE IF NOT EXISTS project_configs (
    project_id   UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    rules_json   JSONB NOT NULL DEFAULT '{}',
    crs_dir      VARCHAR(512) DEFAULT '',
    sensitivity  INT NOT NULL DEFAULT 2,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- mTLS credentials: one client cert per row; fingerprint maps TLS client -> project
CREATE TABLE IF NOT EXISTS mtls_credentials (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id          UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name                VARCHAR(255) NOT NULL,
    client_cert_pem     TEXT NOT NULL,
    cert_fingerprint_sha256 VARCHAR(64) NOT NULL UNIQUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mtls_credentials_project_id ON mtls_credentials(project_id);
CREATE UNIQUE INDEX idx_mtls_credentials_fingerprint ON mtls_credentials(cert_fingerprint_sha256);
