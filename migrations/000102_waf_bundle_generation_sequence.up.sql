-- 000102_waf_bundle_generation_sequence (bug hunt 2026-10-16)
--
-- The WAF agent refuses a bundle whose generation is lower than the one it
-- holds (and keeps that generation in last-bundle.json across restarts).
-- The counter lived in the agent's own waf_agent_bundles row and restarted
-- at 1: an agent deleted in the dashboard and re-registered under the same
-- name got a new row, and every push failed "stale WAF bundle generation"
-- until the new counter passed the old one -- the agent served the old
-- configuration meanwhile.
--
-- Generations now come from one sequence for all rows: every insert and
-- every change of waf_agent_bundles.generation takes nextval, whatever value
-- the statement wrote (the repository's "generation + 1" / "1" statements
-- are unchanged). A re-created row therefore always starts above anything
-- issued before. The sequence starts at the current Unix time in seconds
-- (or the highest stored generation, if larger): rows already deleted held
-- small per-row counters, so agents stuck on such a number today recover
-- with the next push. Seconds keep the value within JavaScript's exact
-- integer range for the dashboard.
--
-- Every existing row is bumped once here so a connected agent receives a
-- generation above the floor on its next connection (the control plane
-- restart for this migration reconnects every agent); its content is
-- unchanged, the agent re-applies the same configuration.

CREATE SEQUENCE IF NOT EXISTS waf_bundle_generation_seq AS BIGINT;

SELECT setval('waf_bundle_generation_seq',
              GREATEST((SELECT COALESCE(MAX(generation), 0) FROM waf_agent_bundles),
                       extract(epoch FROM now())::bigint));

CREATE OR REPLACE FUNCTION waf_agent_bundles_next_generation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' OR NEW.generation IS DISTINCT FROM OLD.generation THEN
        NEW.generation := nextval('waf_bundle_generation_seq');
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS waf_agent_bundles_generation ON waf_agent_bundles;
CREATE TRIGGER waf_agent_bundles_generation
    BEFORE INSERT OR UPDATE OF generation ON waf_agent_bundles
    FOR EACH ROW EXECUTE FUNCTION waf_agent_bundles_next_generation();

UPDATE waf_agent_bundles SET generation = generation + 1, updated_at = NOW();
