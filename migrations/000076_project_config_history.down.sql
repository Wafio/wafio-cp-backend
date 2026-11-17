ALTER TABLE waf_app_config_history DROP COLUMN project_sensitivity;
ALTER TABLE waf_app_config_history DROP COLUMN project_rules_json;
ALTER TABLE waf_app_config_history DROP COLUMN project_revision;
DROP TABLE waf_project_config_history;
ALTER TABLE projects DROP COLUMN waf_config_revision;
