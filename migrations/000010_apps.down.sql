DROP INDEX IF EXISTS idx_ebpf_agents_project;
ALTER TABLE ebpf_agents DROP COLUMN IF EXISTS project_id;
DROP TABLE IF EXISTS deployments;
DROP TABLE IF EXISTS apps;
