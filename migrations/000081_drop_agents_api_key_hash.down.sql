-- 000081 down: restore the pre-000081 schema. Neither the ebpf_agents view
-- nor agents.api_key_hash existed then: 000031 dropped both and nothing
-- recreated them, so 000081 up's DROP COLUMN was a no-op. Recreating the view
-- here (as this file used to) left it depending on
-- agents.last_connections_json and blocked 000052 down.
DROP VIEW IF EXISTS ebpf_agents;
