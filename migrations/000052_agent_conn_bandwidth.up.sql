-- Migration 000052: Add connection and bandwidth snapshot JSONB columns to agents.
-- Replaces Manticore ebpf_connections and ebpf_bandwidth tables.
-- These are "latest snapshot" stores — the full snapshot replaces the previous one.

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS last_connections_json jsonb,
    ADD COLUMN IF NOT EXISTS last_bandwidth_json    jsonb;
