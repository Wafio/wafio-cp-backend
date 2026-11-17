-- Reverse 000082: restore Tag-only container runtime rules (action,
-- severity, description, conditions without the comm term, tags as before
-- 000082), drop the calibration rules added here.
UPDATE trace_detection_rules SET action = 'tag', severity_override = NULL, description = 'Record a UID change under container-runtime ancestry without assuming it is benign.', conditions = '[{"field":"event_name","op":"eq","value":"setuid"},{"field":"parent_comm","op":"in","value":["runc","runc:[2:INIT]","containerd-shim","containerd-shim-runc-v2","containerd"]}]'::jsonb, tags = ARRAY['container','credential-change']::text[], updated_at = NOW() WHERE built_in = true AND name = 'Tag container runtime setuid';
UPDATE trace_detection_rules SET action = 'tag', severity_override = NULL, description = 'Record a GID change under container-runtime ancestry without assuming it is benign.', conditions = '[{"field":"event_name","op":"eq","value":"setgid"},{"field":"parent_comm","op":"in","value":["runc","runc:[2:INIT]","containerd-shim","containerd-shim-runc-v2","containerd"]}]'::jsonb, tags = ARRAY['container','credential-change']::text[], updated_at = NOW() WHERE built_in = true AND name = 'Tag container runtime setgid';
DELETE FROM trace_detection_rules WHERE built_in = true AND name IN (
  'Downgrade sshd privilege separation credential change',
  'Downgrade sshd host key reads',
  'Downgrade sshd account database reads',
  'Downgrade netlink local IPC socket',
  'Downgrade cron daemon spool access',
  'Downgrade pg_isready shadow read',
  'Escalate shell or interpreter root uid request'
);
