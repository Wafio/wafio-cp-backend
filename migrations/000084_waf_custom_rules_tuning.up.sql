-- Custom Rules v2: engine tuning mode + v2 condition knobs.
-- mode 'tuning' rules carry a JSON tuning config (scope x target x detector).
ALTER TABLE waf_custom_rules
    DROP CONSTRAINT waf_custom_rules_mode_check,
    ADD CONSTRAINT waf_custom_rules_mode_check CHECK (mode IN ('gui', 'script', 'tuning'));

ALTER TABLE waf_custom_rules
    ADD COLUMN IF NOT EXISTS tuning JSONB;
