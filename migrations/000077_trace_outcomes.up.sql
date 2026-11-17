-- Preserve exact process identity and outcomes in cold trace evidence.
-- Historical rows are unknown, never retroactively successful.
ALTER TABLE host_security_events
  ADD COLUMN process_start_ns text NOT NULL DEFAULT '',
  ADD COLUMN signal_outcome text NOT NULL DEFAULT 'unknown',
  ADD COLUMN signal_error integer,
  ADD COLUMN activity_outcome text NOT NULL DEFAULT 'unknown';
