-- 000111_runtime_system_service_noise (runtime-security noise)
--
-- Measured on the demo host over a week (2026-10-16):
-- * systemd builds each unit's sandbox with bind mounts in the child it forks
--   and names "(<binary>)" before exec — "(fwupdmgr)", "(systemd-netwo)",
--   "(mandb)", "(logrotate)" …: over 13,000 HIGH mount events a week.
-- * systemctl, the systemd environment generator ("30-systemd-envi"),
--   needrestart and cloud-id read /proc/1/environ at login, motd refresh or
--   package runs; the process × file matrix escalated them to HIGH.
-- New built-ins (priorities 39 and 44) keep both at MEDIUM, tagged
-- unverified-identity (names and lineage are set by the processes, so never
-- lower and never a suppress). The flag a user can edit on a built-in is
-- never written; new rows take the column default (on). Custom rules are not
-- touched. Hosts seeded after this migration get the same rules from
-- builtinRules (trace_rules_builtin.go).

INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade systemd unit sandbox mounts', 'systemd sets up each unit''s sandbox (ProtectSystem, PrivateTmp, InaccessiblePaths) with bind mounts made in the child it forks for the unit, named "(<binary>)" until it execs. Kept at MEDIUM and tagged, only for root, a parenthesised name and a systemd parent whose own parent is the kernel (PID 1).', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"mount"},{"field":"comm","op":"glob","value":"(*)"},{"field":"parent_comm","op":"eq","value":"systemd"},{"field":"grandparent_comm","op":"eq","value":"swapper/0"},{"field":"uid","op":"eq","value":0}]'::jsonb, 2, 39, ARRAY(SELECT jsonb_array_elements_text('["systemd","sandbox","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade systemd unit sandbox mounts' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade PID 1 environment reads by system tools', 'systemctl, the systemd environment generator, needrestart and cloud-id read PID 1''s environment (/proc/1/environ) at login, motd refresh or package runs. Read-only opens by these names are kept at MEDIUM and tagged; any other reader keeps its severity.', true, 'downgrade', '[{"field":"comm","op":"in","value":["systemctl","30-systemd-envi","needrestart","cloud-id","systemd-detect-"]},{"field":"filename","op":"eq","value":"/proc/1/environ"},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb, 2, 44, ARRAY(SELECT jsonb_array_elements_text('["systemd","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade PID 1 environment reads by system tools' AND r.built_in);
