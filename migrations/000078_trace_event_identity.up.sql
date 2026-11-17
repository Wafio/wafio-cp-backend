-- Preserve the agent's boot/raw-nanosecond identity beyond PostgreSQL timestamp precision.
ALTER TABLE host_security_events ADD COLUMN event_id text NOT NULL DEFAULT '';
CREATE INDEX host_security_events_agent_event_identity
  ON host_security_events (agent_id, event_id, event_time)
  WHERE event_id <> '';
