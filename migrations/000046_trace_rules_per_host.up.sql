-- Scope detection rules per host instead of per project.
-- Feature is new (migration 000045); table has no production data — safe to truncate.
TRUNCATE TABLE trace_detection_rules;

ALTER TABLE trace_detection_rules
  ADD COLUMN host_id UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE;

-- Replace project-only indexes with host-scoped indexes.
DROP INDEX IF EXISTS idx_tdr_project_enabled;
DROP INDEX IF EXISTS idx_tdr_project_priority;

CREATE INDEX idx_tdr_host_enabled  ON trace_detection_rules (host_id) WHERE enabled = true;
CREATE INDEX idx_tdr_host_priority ON trace_detection_rules (host_id, priority);
