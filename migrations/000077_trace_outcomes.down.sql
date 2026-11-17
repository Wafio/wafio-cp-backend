ALTER TABLE host_security_events
  DROP COLUMN process_start_ns,
  DROP COLUMN signal_outcome,
  DROP COLUMN signal_error,
  DROP COLUMN activity_outcome;
