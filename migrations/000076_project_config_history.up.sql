ALTER TABLE projects ADD COLUMN waf_config_revision bigint NOT NULL DEFAULT 0;
CREATE TABLE waf_project_config_history (
 project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 revision bigint NOT NULL,
 rules_json jsonb,
 crs_dir text NOT NULL DEFAULT '',
 sensitivity int NOT NULL DEFAULT 2,
 actor_user_id uuid,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(project_id,revision)
);
ALTER TABLE waf_app_config_history ADD COLUMN project_revision bigint;
ALTER TABLE waf_app_config_history ADD COLUMN project_rules_json jsonb;
ALTER TABLE waf_app_config_history ADD COLUMN project_sensitivity int;
