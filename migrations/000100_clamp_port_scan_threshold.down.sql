-- 000100_clamp_port_scan_threshold (DOWN)
-- Irreversible data normalisation: the original thresholds (33-128) are not
-- kept, and the dataplane never enforced them (it logged instead of
-- detecting). Rolling back the schema version leaves the value at 32. The
-- statement keeps the file non-empty.
SELECT 1;
