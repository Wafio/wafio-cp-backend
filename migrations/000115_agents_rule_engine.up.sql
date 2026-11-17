-- Whether the WAF agent has the rule-based (CRS) engine, from its Hello.
--
-- rule_engine  TRUE  the agent runs the rule-based engine;
--              FALSE the agent reports it has none (Hello feature
--                    'semantic_only') and inspects with the semantic engines only;
--              NULL  unknown: an agent built before Hello.features existed, or
--                    a host/eBPF agent, for which the question does not apply.
--
-- Written on every connect, so an agent replaced by another build is
-- rewritten. The dashboard shows it per application, where the project's rule
-- engine setting has no effect on an agent without the engine.
--
-- Metadata-only ALTER on a small table; lock_timeout bounds a wait behind a
-- long reader the same way as 000099 (rerun is safe: IF NOT EXISTS).
SET lock_timeout = '5s';

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS rule_engine BOOLEAN;

RESET lock_timeout;
