ALTER TABLE agents
    DROP COLUMN IF EXISTS last_connections_json,
    DROP COLUMN IF EXISTS last_bandwidth_json;
