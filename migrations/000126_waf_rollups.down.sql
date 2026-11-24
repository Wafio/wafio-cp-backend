-- Reverse 000126: the rollups are derived from waf_decisions and the control plane fills them again
-- after an up migration.
DROP TABLE IF EXISTS waf_rollup_hour;
DROP TABLE IF EXISTS waf_rollup_addr_seen;
DROP TABLE IF EXISTS waf_rollup_minute;
DROP TABLE IF EXISTS waf_rollup_state;
