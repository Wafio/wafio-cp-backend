-- 000106_runtime_auth_session_noise (runtime-security noise)
--
-- Measured on the demo host 2026-10-16: an ordinary SSH login, sudo and the
-- systemd user-session start produced ~30 HIGH/CRITICAL events each.
--
-- * "Escalate /etc/shadow read by unknown process" gains event_name =
--   openat. The trace object reused a per-CPU scratch event without clearing
--   its filename, so sendto, connect, socket, accept and kill events carried
--   the path of the previous open on that CPU (often /etc/shadow), and this
--   rule, which had no event condition, escalated them to CRITICAL. The agent
--   and the control plane now also drop that stale filename.
-- * New built-ins (priorities 14-19, 37-38 and 41-43): verified sshd-session /
--   sshd-auth and PID 1's forked children "(systemd)" / "(sd-pam)" changing
--   IDs or reading /etc/shadow, and PID 1 loading BPF programs, go to LOW
--   only with exe_verified. Exec'd helpers no host binary check can vouch
--   for (sudo/su/login/cron setgid, unix_chkpwd under an auth parent,
--   systemd-user-runtime-dir mounting a tmpfs, and — priorities 37-38 — an
--   unverified root "(systemd)" user-session setup reading /etc/shadow or a
--   non-root systemd --user loading BPF, both with a systemd parent) go to
--   MEDIUM, tagged unverified-identity. Root setting root ownership under /usr or /opt goes
--   to LOW.
-- Existing built-in rows get only the one conditions change; the flag a user
-- can edit on a built-in and the row IDs are never written. New rows take the
-- column default (on). Custom rules are not touched. Hosts seeded after this
-- migration get the same library from builtinRules (trace_rules_builtin.go).

UPDATE trace_detection_rules SET conditions = '[{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"eq","value":"/etc/shadow"},{"field":"comm","op":"not_in","value":["sshd","sshd-session","sshd-auth","login","passwd","chage","useradd","usermod","pg_isready","postgres","shadow","unix_chkpwd","ansible","chef-client","puppet","osqueryi","aide","tripwire","restic","borg","bacula-fd","urbackupclient","backuppc"]}]'::jsonb, updated_at = NOW() WHERE built_in = true AND name = 'Escalate /etc/shadow read by unknown process';
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade verified auth daemon credential change', 'OpenSSH (sshd-session, sshd-auth) and the systemd user-session setup switch user and group IDs on every login. Only for a process the kernel saw in the agent-verified protected set; a process merely named sshd-auth keeps its severity.', true, 'downgrade', '[{"field":"comm","op":"in","value":["sshd","sshd-session","sshd-auth","(systemd)","(sd-pam)"]},{"field":"event_name","op":"in","value":["setuid","setgid"]},{"field":"exe_verified","op":"eq","value":true}]'::jsonb, 1, 14, ARRAY(SELECT jsonb_array_elements_text('["auth","credential-change","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade verified auth daemon credential change' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade auth helper group change', 'sudo, su, login and cron run set-user-ID root and set the group ID (setgid(0) included) while switching identity. These helpers are exec''d, so the agent cannot verify them: the event is kept at MEDIUM and tagged. A setuid(0) from such a name stays at its severity.', true, 'downgrade', '[{"field":"comm","op":"in","value":["sudo","sudoedit","su","runuser","login","cron","crond","atd"]},{"field":"event_name","op":"eq","value":"setgid"}]'::jsonb, 2, 15, ARRAY(SELECT jsonb_array_elements_text('["auth","credential-change","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade auth helper group change' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade verified auth daemon account database reads', 'sshd-session and the systemd user-session setup read /etc/shadow through PAM (pam_unix account checks) on every login. Only for a process the kernel saw in the agent-verified protected set; any other reader keeps HIGH or is escalated.', true, 'downgrade', '[{"field":"comm","op":"in","value":["sshd","sshd-session","sshd-auth","(systemd)","(sd-pam)"]},{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"in","value":["/etc/shadow","/etc/gshadow"]},{"field":"exe_verified","op":"eq","value":true},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb, 1, 17, ARRAY(SELECT jsonb_array_elements_text('["auth","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade verified auth daemon account database reads' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade unix_chkpwd shadow read under an auth parent', 'pam_unix runs the unix_chkpwd helper to check a password or account against /etc/shadow; that is its only job. The helper is exec''d and cannot be verified, so the read is kept at MEDIUM and tagged, and only when the parent is an authentication process.', true, 'downgrade', '[{"field":"comm","op":"eq","value":"unix_chkpwd"},{"field":"parent_comm","op":"in","value":["sshd","sshd-session","sshd-auth","sudo","sudoedit","su","runuser","login","cron","crond","atd","(systemd)","polkitd","polkit-agent-he","gdm-session-wor","lightdm","sddm-helper"]},{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"eq","value":"/etc/shadow"},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb, 2, 18, ARRAY(SELECT jsonb_array_elements_text('["auth","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade unix_chkpwd shadow read under an auth parent' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade verified systemd BPF programs', 'systemd (PID 1) loads cgroup BPF programs (device policy, IP accounting and firewalling) whenever it starts a unit, including every user session. Only for a process the kernel saw as PID 1 or in the agent-verified protected set.', true, 'downgrade', '[{"field":"comm","op":"eq","value":"systemd"},{"field":"event_name","op":"eq","value":"bpf"},{"field":"exe_verified","op":"eq","value":true}]'::jsonb, 1, 19, ARRAY(SELECT jsonb_array_elements_text('["systemd","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade verified systemd BPF programs' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade systemd-user-runtime-dir tmpfs mount', 'systemd-user-runtime-dir mounts a tmpfs on /run/user/<uid> (through an O_PATH descriptor, so the target shows as /proc/self/fd/N) when a user''s first session starts. The helper is exec''d and cannot be verified: kept at MEDIUM and tagged, only for root, a tmpfs and a systemd parent.', true, 'downgrade', '[{"field":"comm","op":"eq","value":"systemd-user-ru"},{"field":"parent_comm","op":"eq","value":"systemd"},{"field":"event_name","op":"eq","value":"mount"},{"field":"filename","op":"eq","value":"tmpfs"},{"field":"uid","op":"eq","value":0}]'::jsonb, 2, 41, ARRAY(SELECT jsonb_array_elements_text('["systemd","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade systemd-user-runtime-dir tmpfs mount' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade root chown to root under /usr', 'Package managers and installers running as root set root ownership on what they install under /usr. Changing a file''s owner to root needs root already, so it adds no privilege; a set-user-ID bit is a separate chmod event that stays HIGH. Ownership changes elsewhere (/tmp, /dev/shm, home directories, unresolved paths) keep HIGH.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"chown"},{"field":"uid","op":"eq","value":0},{"field":"detail","op":"eq","value":0},{"field":"filename","op":"starts_with","value":"/usr/"}]'::jsonb, 1, 42, ARRAY(SELECT jsonb_array_elements_text('["install","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade root chown to root under /usr' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade root chown to root under /opt', 'Installers running as root set root ownership on what they install under /opt (for example /opt/wafio). Changing a file''s owner to root needs root already; a set-user-ID bit is a separate chmod event that stays HIGH.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"chown"},{"field":"uid","op":"eq","value":0},{"field":"detail","op":"eq","value":0},{"field":"filename","op":"starts_with","value":"/opt/"}]'::jsonb, 1, 43, ARRAY(SELECT jsonb_array_elements_text('["install","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade root chown to root under /opt' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade systemd user-session setup shadow read', 'When a user''s first session starts, PID 1 forks the user manager, which runs as "(systemd)" (root) and reads /etc/shadow through PAM before it becomes systemd --user. When the kernel did not mark it verified, the read is kept at MEDIUM and tagged, only for root, a read-only open and a systemd parent.', true, 'downgrade', '[{"field":"comm","op":"in","value":["(systemd)","(sd-pam)"]},{"field":"parent_comm","op":"eq","value":"systemd"},{"field":"uid","op":"eq","value":0},{"field":"filename","op":"eq","value":"/etc/shadow"},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb, 2, 37, ARRAY(SELECT jsonb_array_elements_text('["auth","systemd","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade systemd user-session setup shadow read' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade systemd user manager BPF programs', 'systemd --user (a user''s service manager, forked by PID 1) loads cgroup BPF programs for the user''s units. It runs as the user and cannot be verified, so the event is kept at MEDIUM and tagged, only for a non-root systemd whose parent is systemd.', true, 'downgrade', '[{"field":"comm","op":"eq","value":"systemd"},{"field":"parent_comm","op":"eq","value":"systemd"},{"field":"uid","op":"neq","value":0},{"field":"event_name","op":"eq","value":"bpf"}]'::jsonb, 2, 38, ARRAY(SELECT jsonb_array_elements_text('["systemd","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade systemd user manager BPF programs' AND r.built_in);
