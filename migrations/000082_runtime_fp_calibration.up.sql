-- FP calibration: severity for measured noise sources (24h data).
-- Container runtime credential changes: Tag -> Downgrade (evidence retained,
-- description marked, credential-change tag kept). New lineage-tight rules
-- for sshd privilege separation, host key/account database reads, AF_NETLINK
-- local IPC sockets, cron spool access, pg_isready shadow reads; interpreter
-- setuid(0) stays loud via escalation.

UPDATE trace_detection_rules SET action = 'downgrade', severity_override = 1, description = 'Container runtime init requesting root is the standard lifecycle (runc unprivileged child regains root). Downgraded, still recorded.', conditions = '[{"field":"event_name","op":"eq","value":"setuid"},{"field":"comm","op":"starts_with","value":"runc"},{"field":"parent_comm","op":"in","value":["runc","runc:[2:INIT]","containerd-shim","containerd-shim-runc-v2","containerd"]}]'::jsonb, tags = ARRAY(SELECT jsonb_array_elements_text('["container","credential-change","expected"]'::jsonb)), updated_at = NOW() WHERE built_in = true AND name = 'Tag container runtime setuid';
UPDATE trace_detection_rules SET action = 'downgrade', severity_override = 1, description = 'Container runtime init requesting a GID change is the standard lifecycle. Downgraded, still recorded.', conditions = '[{"field":"event_name","op":"eq","value":"setgid"},{"field":"comm","op":"starts_with","value":"runc"},{"field":"parent_comm","op":"in","value":["runc","runc:[2:INIT]","containerd-shim","containerd-shim-runc-v2","containerd"]}]'::jsonb, tags = ARRAY(SELECT jsonb_array_elements_text('["container","credential-change","expected"]'::jsonb)), updated_at = NOW() WHERE built_in = true AND name = 'Tag container runtime setgid';

INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, enabled, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade sshd privilege separation credential change', 'OpenSSH privilege separation: the unprivileged pre-auth child regains root via setuid(0) after successful authentication. Three-generation sshd lineage is the normal pattern.', true, true, 'downgrade', '[{"field":"comm","op":"eq","value":"sshd"},{"field":"parent_comm","op":"eq","value":"sshd"},{"field":"grandparent_comm","op":"eq","value":"sshd"},{"field":"event_name","op":"in","value":["setuid","setgid"]}]'::jsonb, 1, 4, ARRAY(SELECT jsonb_array_elements_text('["ssh","privilege-separation","credential-change","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade sshd privilege separation credential change' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, enabled, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade sshd host key reads', 'sshd loads its own host keys on every connection. Reading /etc/ssh/* is the daemon doing its job.', true, true, 'downgrade', '[{"field":"comm","op":"eq","value":"sshd"},{"field":"parent_comm","op":"eq","value":"sshd"},{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"starts_with","value":"/etc/ssh/"},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb, 1, 5, ARRAY(SELECT jsonb_array_elements_text('["ssh","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade sshd host key reads' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, enabled, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade sshd account database reads', 'sshd reads the account database during authentication and session setup.', true, true, 'downgrade', '[{"field":"comm","op":"eq","value":"sshd"},{"field":"parent_comm","op":"eq","value":"sshd"},{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"in","value":["/etc/passwd","/etc/shadow","/etc/group","/etc/gshadow","/etc/nsswitch.conf"]},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb, 1, 7, ARRAY(SELECT jsonb_array_elements_text('["ssh","auth","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade sshd account database reads' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, enabled, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade netlink local IPC socket', 'AF_NETLINK sockets are kernel-local IPC (audit, udev, systemd), not network activity. Never a network intrusion signal.', true, true, 'downgrade', '[{"field":"event_name","op":"eq","value":"socket"},{"field":"addr_family","op":"eq","value":16}]'::jsonb, 0, 8, ARRAY(SELECT jsonb_array_elements_text('["netlink","local-ipc","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade netlink local IPC socket' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, enabled, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade cron daemon spool access', 'crond reading /var/spool/cron is how scheduled jobs are discovered.', true, true, 'downgrade', '[{"field":"comm","op":"in","value":["cron","crond"]},{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"starts_with","value":"/var/spool/cron/"},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb, 1, 9, ARRAY(SELECT jsonb_array_elements_text('["cron","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade cron daemon spool access' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, enabled, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade pg_isready shadow read', 'pg_isready health checks touch the account database through libwrap resolution. The read is bounded and expected.', true, true, 'downgrade', '[{"field":"comm","op":"eq","value":"pg_isready"},{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"eq","value":"/etc/shadow"},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb, 1, 10, ARRAY(SELECT jsonb_array_elements_text('["postgresql","health-check","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade pg_isready shadow read' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, enabled, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Escalate shell or interpreter root uid request', 'A shell or interpreter requesting setuid(0) is the classic post-exploitation escalation path and must stay loud.', true, true, 'escalate', '[{"field":"comm","op":"in","value":["bash","sh","dash","zsh","ksh","python","python3","perl","ruby","php","lua"]},{"field":"event_name","op":"eq","value":"setuid"},{"field":"detail","op":"eq","value":0}]'::jsonb, 4, 40, ARRAY(SELECT jsonb_array_elements_text('["credential-change","high-signal"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Escalate shell or interpreter root uid request' AND r.built_in);
