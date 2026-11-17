-- Whether the WAF agent can run script rules, from its Hello.
--
-- script_rules  TRUE  the agent runs script rules;
--               FALSE the agent reports it cannot (Hello feature
--                     'no_script_rules'): a script rule would leave every
--                     request of its application unfinished, which becomes LOG;
--               NULL  unknown: an agent built before Hello.features existed, or
--                     a host/eBPF agent, for which the question does not apply.
--
-- Written on every connect next to rule_engine (000115), so an agent replaced
-- by another build is rewritten. The control plane refuses to create or enable
-- a script rule for an application whose agents all report FALSE.
--
-- Metadata-only ALTER on a small table; lock_timeout bounds a wait behind a
-- long reader the same way as 000115 (rerun is safe: IF NOT EXISTS).
SET lock_timeout = '5s';

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS script_rules BOOLEAN;

RESET lock_timeout;
