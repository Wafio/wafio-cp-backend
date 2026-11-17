-- Add desired_state JSONB to agents for gRPC-based eBPF state management.
-- This column stores the control-plane's authoritative desired state for each
-- eBPF agent (config, blocklist, allowlist, geo_blocked, port_policies, egress).
-- The server pushes this state to the agent via gRPC BundleUpdate on connect
-- and on every write. The callback_url column was removed in 000031.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS desired_state JSONB NOT NULL DEFAULT '{}';
