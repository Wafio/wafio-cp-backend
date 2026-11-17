-- 000102_waf_bundle_generation_sequence (DOWN)
-- Back to per-row counters. Stored generations keep their (large) values, so
-- no agent sees a lower generation for its row; a row created after this
-- down step starts at 1 again (the pre-000102 behaviour).
DROP TRIGGER IF EXISTS waf_agent_bundles_generation ON waf_agent_bundles;
DROP FUNCTION IF EXISTS waf_agent_bundles_next_generation();
DROP SEQUENCE IF EXISTS waf_bundle_generation_seq;
