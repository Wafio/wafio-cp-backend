-- Per-WAF-agent inline proxy listen port. NULL → use default 8090
-- (i.e. whatever the agent was started with). When set via UI/API, the
-- control plane includes this in the bundle and the agent gracefully
-- rebinds its inline reverse-proxy listener.
ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS proxy_listen_port INTEGER;

-- Sanity bound: standard TCP port range.
ALTER TABLE agents
    ADD CONSTRAINT agents_proxy_listen_port_range
    CHECK (proxy_listen_port IS NULL OR (proxy_listen_port BETWEEN 1 AND 65535));
