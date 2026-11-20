-- Reverse 000125: remove the four WAF agent TLS key rules and give the read rule the description
-- and conditions it had after 000121. The flag a user can edit on a built-in is never written.

DELETE FROM trace_detection_rules WHERE built_in = true AND name = 'Downgrade verified WAF agent TLS key writes';
DELETE FROM trace_detection_rules WHERE built_in = true AND name = 'Downgrade verified WAF agent TLS key removals';
DELETE FROM trace_detection_rules WHERE built_in = true AND name = 'Downgrade verified WAF agent TLS key mode changes';
DELETE FROM trace_detection_rules WHERE built_in = true AND name = 'Downgrade verified WAF agent TLS key renames';
UPDATE trace_detection_rules SET description = 'The WAF agent reads its own TLS keys under /etc/ssl/private and /etc/letsencrypt/live at start, on reload and on a poll, as an unprivileged user. Only for a non-root process the agent verified as the WAF agent binary, under a thread name the WAF agent uses. A write, any other file, an unverified reader and any other name keep their severity.', conditions = '[{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"starts_with_any","value":["/etc/ssl/private/","/etc/letsencrypt/live/"]},{"field":"comm","op":"in","value":["wafio-waf-agent","tokio-rt-worker"]},{"field":"uid","op":"neq","value":0},{"field":"exe_verified","op":"eq","value":true},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb WHERE built_in = true AND name = 'Downgrade verified WAF agent TLS key reads';
