-- 000017_analyze_method
-- Add analyze_method column to waf_decisions to track which detection
-- engine produced the decision: semantic, rule_based, hybrid, policy, geo,
-- bot, body_limit.
--
-- Existing rows get NULL (unknown); new rows will be populated by the WAF engine.

ALTER TABLE waf_decisions
    ADD COLUMN IF NOT EXISTS analyze_method VARCHAR(32);

CREATE INDEX IF NOT EXISTS idx_waf_decisions_analyze_method
    ON waf_decisions (analyze_method)
    WHERE analyze_method IS NOT NULL;
