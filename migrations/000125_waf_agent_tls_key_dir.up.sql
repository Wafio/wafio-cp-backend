-- 000125_waf_agent_tls_key_dir (runtime-security noise)
--
-- The WAF agent that terminates TLS keeps its certificate keys and its ACME account key under
-- /var/lib/wafio-waf-agent/tls/, as an unprivileged user. It reads them at start, on reload and
-- on a poll, and it writes them when it installs or renews a certificate: a new file next to the
-- old one, a rename into place, the removal of what it replaced and a chmod. The classifier rates
-- the directory as credential material, so each open of a key there by a process that is not root
-- is a CRITICAL incident, under the agent's process name and under the name of its tokio threads,
-- and its renames, removals and mode changes there are changes to credential files.
--
-- Two kinds of change, as 000121 did for /etc/ssl/private and /etc/letsencrypt/live:
--   - "Downgrade verified WAF agent TLS key reads" also covers the key directory (description
--     and conditions only);
--   - four new built-ins, one for each event, on the priorities after the 000122 rules:
--       74  openat with a write flag (bit_and 579: O_WRONLY, O_RDWR, O_CREAT, O_TRUNC)
--       75  unlink
--       76  chmod to a mode with no setuid, setgid or sticky bit and no group or other bit
--           (bit_none 3647)
--       77  rename with the old path and the new path (args) both under the directory
--     Each goes to LOW (stored, no incident, tagged expected) when exe_verified is set, the real
--     UID is not 0 and comm is wafio-waf-agent or tokio-rt-worker. A separate rule for each,
--     because every condition of a rule is required and the flags of these events mean different
--     things. A read-only open is the read rule's, so with that rule off it is as loud as before;
--     a file moved or exchanged out of the directory, and a wide mode, stay as loud as before.
-- Any other process, a path outside the directory once cleaned and an unverified writer keep
-- their severity. The flag a user can edit on a built-in and the row IDs are never written; the
-- new rows take the column default (on). Custom rules are not touched. Hosts seeded after this
-- migration get the same rules from builtinRules (trace_rules_builtin.go).

UPDATE trace_detection_rules SET description = 'The WAF agent reads its own TLS keys under /etc/ssl/private, /etc/letsencrypt/live and /var/lib/wafio-waf-agent/tls at start, on reload and on a poll, as an unprivileged user. Only for a non-root process the agent verified as the WAF agent binary, under a thread name the WAF agent uses. A write, any other file, an unverified reader and any other name keep their severity.', conditions = '[{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"starts_with_any","value":["/etc/ssl/private/","/etc/letsencrypt/live/","/var/lib/wafio-waf-agent/tls/"]},{"field":"comm","op":"in","value":["wafio-waf-agent","tokio-rt-worker"]},{"field":"uid","op":"neq","value":0},{"field":"exe_verified","op":"eq","value":true},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb WHERE built_in = true AND name = 'Downgrade verified WAF agent TLS key reads';
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade verified WAF agent TLS key writes', 'The WAF agent creates and rewrites its own TLS keys under /var/lib/wafio-waf-agent/tls when it installs or renews a certificate, as an unprivileged user. Only for an open for writing, by a non-root process the agent verified as the WAF agent binary, under a thread name the WAF agent uses. A read-only open, any other file, any other process and an unverified writer keep their severity.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"starts_with","value":"/var/lib/wafio-waf-agent/tls/"},{"field":"flags","op":"bit_and","value":579},{"field":"comm","op":"in","value":["wafio-waf-agent","tokio-rt-worker"]},{"field":"uid","op":"neq","value":0},{"field":"exe_verified","op":"eq","value":true}]'::jsonb, 1, 74, ARRAY(SELECT jsonb_array_elements_text('["wafio","tls","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade verified WAF agent TLS key writes' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade verified WAF agent TLS key removals', 'The WAF agent removes the TLS key files it replaced under /var/lib/wafio-waf-agent/tls when it installs or renews a certificate, as an unprivileged user. Only for a non-root process the agent verified as the WAF agent binary, under a thread name the WAF agent uses. Any other file, any other process and an unverified process keep their severity.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"unlink"},{"field":"filename","op":"starts_with","value":"/var/lib/wafio-waf-agent/tls/"},{"field":"comm","op":"in","value":["wafio-waf-agent","tokio-rt-worker"]},{"field":"uid","op":"neq","value":0},{"field":"exe_verified","op":"eq","value":true}]'::jsonb, 1, 75, ARRAY(SELECT jsonb_array_elements_text('["wafio","tls","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade verified WAF agent TLS key removals' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade verified WAF agent TLS key mode changes', 'The WAF agent sets the mode of its own TLS key files under /var/lib/wafio-waf-agent/tls to owner only, as an unprivileged user. Only for a mode with no setuid, setgid or sticky bit and no permission for the group or others, by a non-root process the agent verified as the WAF agent binary, under a thread name the WAF agent uses. A wider mode, any other file, any other process and an unverified process keep their severity.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"chmod"},{"field":"filename","op":"starts_with","value":"/var/lib/wafio-waf-agent/tls/"},{"field":"flags","op":"bit_none","value":3647},{"field":"comm","op":"in","value":["wafio-waf-agent","tokio-rt-worker"]},{"field":"uid","op":"neq","value":0},{"field":"exe_verified","op":"eq","value":true}]'::jsonb, 1, 76, ARRAY(SELECT jsonb_array_elements_text('["wafio","tls","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade verified WAF agent TLS key mode changes' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade verified WAF agent TLS key renames', 'The WAF agent renames a new TLS key file into place under /var/lib/wafio-waf-agent/tls when it installs or renews a certificate, as an unprivileged user. Only when the old and the new path are both under that directory, for a non-root process the agent verified as the WAF agent binary, under a thread name the WAF agent uses. A file moved or exchanged out of the directory, any other file, any other process and an unverified process keep their severity.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"rename"},{"field":"filename","op":"starts_with","value":"/var/lib/wafio-waf-agent/tls/"},{"field":"args","op":"starts_with","value":"/var/lib/wafio-waf-agent/tls/"},{"field":"comm","op":"in","value":["wafio-waf-agent","tokio-rt-worker"]},{"field":"uid","op":"neq","value":0},{"field":"exe_verified","op":"eq","value":true}]'::jsonb, 1, 77, ARRAY(SELECT jsonb_array_elements_text('["wafio","tls","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade verified WAF agent TLS key renames' AND r.built_in);
