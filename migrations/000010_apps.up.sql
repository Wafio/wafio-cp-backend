-- Apps: deployable units within a project
CREATE TABLE IF NOT EXISTS apps (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name          VARCHAR(100) NOT NULL,

    -- Git source
    git_url       VARCHAR(512) NOT NULL,
    git_branch    VARCHAR(100) NOT NULL DEFAULT 'main',

    -- Frontend config
    fe_enabled    BOOLEAN NOT NULL DEFAULT false,
    fe_framework  VARCHAR(30),
    fe_build_cmd  VARCHAR(255),
    fe_output_dir VARCHAR(255),
    fe_port       INT NOT NULL DEFAULT 3000,

    -- Backend config
    be_enabled    BOOLEAN NOT NULL DEFAULT false,
    be_runtime    VARCHAR(30),
    be_start_cmd  VARCHAR(255),
    be_port       INT NOT NULL DEFAULT 4000,

    -- Database config
    db_enabled    BOOLEAN NOT NULL DEFAULT false,
    db_engine     VARCHAR(20),

    -- Environment variables (encrypted JSON)
    env_vars      JSONB NOT NULL DEFAULT '{}',

    -- Resource limits
    memory_mb     INT NOT NULL DEFAULT 512,
    cpu_milli     INT NOT NULL DEFAULT 500,
    disk_mb       INT NOT NULL DEFAULT 1024,

    -- Runtime state
    domain        VARCHAR(255),
    container_id  VARCHAR(100),
    image_tag     VARCHAR(255),
    status        VARCHAR(20) NOT NULL DEFAULT 'stopped',
    internal_port INT,

    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(project_id, name)
);

CREATE INDEX idx_apps_project ON apps(project_id);
CREATE INDEX idx_apps_status  ON apps(status);
CREATE INDEX idx_apps_domain  ON apps(domain);

-- Deployments: build & deploy history
CREATE TABLE IF NOT EXISTS deployments (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id        UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    git_commit    VARCHAR(40),
    git_message   VARCHAR(500),
    status        VARCHAR(20) NOT NULL DEFAULT 'pending',
    build_log     TEXT,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at   TIMESTAMPTZ
);

CREATE INDEX idx_deployments_app    ON deployments(app_id);
CREATE INDEX idx_deployments_status ON deployments(status);

-- Link agent to project (add project_id to ebpf_agents)
ALTER TABLE ebpf_agents ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_ebpf_agents_project ON ebpf_agents(project_id);
