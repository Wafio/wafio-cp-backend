-- Remove the per-app waf_threshold column.
-- Threshold configuration is now handled entirely via app_configs.rules_json.
ALTER TABLE apps DROP COLUMN IF EXISTS waf_threshold;
