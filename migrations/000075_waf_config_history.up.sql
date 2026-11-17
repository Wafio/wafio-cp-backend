ALTER TABLE apps ADD COLUMN waf_config_revision bigint NOT NULL DEFAULT 0;
CREATE TABLE waf_app_config_history (
 app_id uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
 project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 revision bigint NOT NULL,
 rules_json jsonb,
 sensitivity int NOT NULL DEFAULT 2,
 actor_user_id uuid,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(app_id,revision)
);
CREATE INDEX waf_app_config_history_project ON waf_app_config_history(project_id,app_id,revision DESC);
