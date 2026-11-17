-- Reverse 000084. Destructive by necessity: a 'tuning' rule has no form
-- under the old ('gui','script') CHECK and its config lives in the column
-- dropped below, so tuning rules are deleted first. Without this the CHECK
-- fails on any tuning row and leaves the database dirty at version 84.
DELETE FROM waf_custom_rules WHERE mode = 'tuning';

ALTER TABLE waf_custom_rules
    DROP CONSTRAINT waf_custom_rules_mode_check,
    ADD CONSTRAINT waf_custom_rules_mode_check CHECK (mode IN ('gui', 'script'));

ALTER TABLE waf_custom_rules
    DROP COLUMN IF EXISTS tuning;
