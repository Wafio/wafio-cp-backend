DROP INDEX IF EXISTS idx_tdr_host_enabled;
DROP INDEX IF EXISTS idx_tdr_host_priority;

ALTER TABLE trace_detection_rules DROP COLUMN IF EXISTS host_id;

CREATE INDEX idx_tdr_project_enabled  ON trace_detection_rules (project_id) WHERE enabled = true;
CREATE INDEX idx_tdr_project_priority ON trace_detection_rules (project_id, priority);
