-- 000017_analyze_method (down)
DROP INDEX IF EXISTS idx_waf_decisions_analyze_method;
ALTER TABLE waf_decisions DROP COLUMN IF EXISTS analyze_method;
