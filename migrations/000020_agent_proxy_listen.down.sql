ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_proxy_listen_port_range;
ALTER TABLE agents DROP COLUMN IF EXISTS proxy_listen_port;
