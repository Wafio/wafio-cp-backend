-- Reverse 000111: remove the two system-service built-ins it added. The flag
-- a user can edit on the remaining rows is never written.

DELETE FROM trace_detection_rules WHERE built_in = true AND name IN (
  'Downgrade systemd unit sandbox mounts',
  'Downgrade PID 1 environment reads by system tools'
);
