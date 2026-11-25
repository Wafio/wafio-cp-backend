-- 000121_waf_agent_tls_key_reads (runtime-security noise)
--
-- The WAF agent serves HTTPS and reads its own TLS key at start, on reload and
-- on a 30 s poll, as an unprivileged user. The process x file matrix rates a
-- credential file CRITICAL for any real UID but 0, so each read opened a
-- CRITICAL incident, under the agent's process name and under the name of its
-- tokio worker threads. A host agent that marks the WAF agent as verified (the
-- kernel saw it in the protected set) lets a rule tell it from any other reader.
--
-- New built-in (priority 62): an open for reading under /etc/ssl/private/ or
-- /etc/letsencrypt/live/ goes to LOW (stored, no incident, tagged expected)
-- when exe_verified is set, the real UID is not 0 and comm is wafio-waf-agent
-- (the process) or tokio-rt-worker (tokio's default thread name; its worker and
-- blocking threads carry it). A write, any other file, a path that leaves those
-- two directories once cleaned, an unverified reader and any other name keep
-- their severity.
--
-- A verified process is no longer always a root daemon. Five built-ins trusted
-- a root daemon's name together with exe_verified: the systemd execve suppress,
-- the dockerd network suppress, the sshd host key and account database
-- downgrades and the auth daemon shadow read downgrade. A thread of a verified
-- non-root process could rename itself to systemd, dockerd or sshd and have an
-- event hidden or lowered. They now also require real UID 0. Only the
-- description and the conditions of those five rows change.
-- The flag a user can edit on a built-in and the row IDs are never written;
-- the new row takes the column default (on). Custom rules are not touched.
-- Hosts seeded after this migration get the same rules from builtinRules
-- (trace_rules_builtin.go).

UPDATE trace_detection_rules SET description = 'systemd calls execve to start services. These are not process injection. Only for a root process the agent verified as the systemd host binary (or its child before exec); the name alone is not enough. Applies only below HIGH severity; process names alone do not justify hiding sensitive observations.', conditions = '[{"field":"comm","op":"eq","value":"systemd"},{"field":"event_name","op":"eq","value":"execve"},{"field":"uid","op":"eq","value":0},{"field":"exe_verified","op":"eq","value":true},{"field":"severity","op":"lte","value":2}]'::jsonb WHERE built_in = true AND name = 'Suppress systemd service start execve';
UPDATE trace_detection_rules SET description = 'dockerd creating/managing network sockets is normal container networking. Only for a root process the agent verified as the dockerd host binary; a process renamed to dockerd is kept. Applies only below HIGH severity; process names alone do not justify hiding sensitive observations.', conditions = '[{"field":"comm","op":"eq","value":"dockerd"},{"field":"category","op":"eq","value":"network"},{"field":"uid","op":"eq","value":0},{"field":"exe_verified","op":"eq","value":true},{"field":"severity","op":"lte","value":2}]'::jsonb WHERE built_in = true AND name = 'Suppress dockerd network management';
UPDATE trace_detection_rules SET description = 'sshd loads its own host keys on every connection. Reading /etc/ssh/* is the daemon doing its job. Only for a root process the agent verified as the sshd host binary.', conditions = '[{"field":"comm","op":"eq","value":"sshd"},{"field":"parent_comm","op":"eq","value":"sshd"},{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"starts_with","value":"/etc/ssh/"},{"field":"uid","op":"eq","value":0},{"field":"exe_verified","op":"eq","value":true},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb WHERE built_in = true AND name = 'Downgrade sshd host key reads';
UPDATE trace_detection_rules SET description = 'sshd reads the account database during authentication and session setup. Only for a root process the agent verified as the sshd host binary: a process and parent renamed to sshd reading /etc/shadow stay HIGH.', conditions = '[{"field":"comm","op":"eq","value":"sshd"},{"field":"parent_comm","op":"eq","value":"sshd"},{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"in","value":["/etc/passwd","/etc/shadow","/etc/group","/etc/gshadow","/etc/nsswitch.conf"]},{"field":"uid","op":"eq","value":0},{"field":"exe_verified","op":"eq","value":true},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb WHERE built_in = true AND name = 'Downgrade sshd account database reads';
UPDATE trace_detection_rules SET description = 'sshd-session and the systemd user-session setup read /etc/shadow through PAM (pam_unix account checks) on every login. Only for a root process the kernel saw in the agent-verified protected set; any other reader keeps HIGH or is escalated.', conditions = '[{"field":"comm","op":"in","value":["sshd","sshd-session","sshd-auth","(systemd)","(sd-pam)"]},{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"in","value":["/etc/shadow","/etc/gshadow"]},{"field":"uid","op":"eq","value":0},{"field":"exe_verified","op":"eq","value":true},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb WHERE built_in = true AND name = 'Downgrade verified auth daemon account database reads';
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade verified WAF agent TLS key reads', 'The WAF agent reads its own TLS keys under /etc/ssl/private and /etc/letsencrypt/live at start, on reload and on a poll, as an unprivileged user. Only for a non-root process the agent verified as the WAF agent binary, under a thread name the WAF agent uses. A write, any other file, an unverified reader and any other name keep their severity.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"starts_with_any","value":["/etc/ssl/private/","/etc/letsencrypt/live/"]},{"field":"comm","op":"in","value":["wafio-waf-agent","tokio-rt-worker"]},{"field":"uid","op":"neq","value":0},{"field":"exe_verified","op":"eq","value":true},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb, 1, 62, ARRAY(SELECT jsonb_array_elements_text('["wafio","tls","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade verified WAF agent TLS key reads' AND r.built_in);
