-- Reverts 000094: listen addresses are no longer unique per WAF agent.
DROP INDEX IF EXISTS uq_waf_agent_apps_listen_addr;
DROP TRIGGER IF EXISTS apps_listen_addr_sync ON apps;
DROP TRIGGER IF EXISTS waf_agent_apps_listen_addr ON waf_agent_apps;
DROP FUNCTION IF EXISTS apps_sync_listen_addr();
DROP FUNCTION IF EXISTS waf_agent_apps_copy_listen_addr();
ALTER TABLE waf_agent_apps
    DROP COLUMN IF EXISTS listen_port,
    DROP COLUMN IF EXISTS listen_host_key;
DROP FUNCTION IF EXISTS wafio_listen_host_key(text);
