-- Project-scoped membership with role (owner | member).
-- Admins bypass this table entirely (they can access all projects).
CREATE TABLE IF NOT EXISTS project_members (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    role       VARCHAR(50) NOT NULL DEFAULT 'member', -- 'owner' | 'member'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, user_id)
);

CREATE INDEX idx_project_members_project_id ON project_members(project_id);
CREATE INDEX idx_project_members_user_id    ON project_members(user_id);

-- Seed: every existing project creator becomes owner of their project.
-- projects.user_id holds the creator; cross-join covers the case where
-- admins already have access to all projects they may have created.
INSERT INTO project_members (project_id, user_id, role)
SELECT p.id, p.user_id, 'owner'
FROM   projects p
ON CONFLICT DO NOTHING;
