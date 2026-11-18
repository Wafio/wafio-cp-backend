-- Maintenance mode of an application, and whether the WAF agent supports it.
--
-- apps.maintenance          the stored maintenance object: enabled, message,
--                           end_time, custom_html, allow_ips, allow_paths and
--                           started_at. '{}' means never configured, which is
--                           off. It is not part of rules_json (a change there
--                           would force a policy override on the application)
--                           and not part of proxy_config (the Routing form
--                           replaces that whole).
-- agents.maintenance_mode   TRUE  the agent answers with the maintenance page
--                                 (Hello feature 'maintenance_mode');
--                           FALSE the agent sent features without it;
--                           NULL  unknown: no Hello feature list yet, or a host
--                                 agent, for which the question does not apply.
--                           Written on every connect, like script_rules (000116).
--                           The control plane refuses to turn maintenance on for
--                           an application whose agent reports FALSE.
--
-- Both ALTERs are metadata-only (a constant default needs no table rewrite).
-- lock_timeout bounds a wait behind a long reader the same way as 000116
-- (rerun is safe: IF NOT EXISTS).
SET lock_timeout = '5s';

ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS maintenance JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS maintenance_mode BOOLEAN;

RESET lock_timeout;
