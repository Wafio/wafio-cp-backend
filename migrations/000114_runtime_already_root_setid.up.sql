-- 000114_runtime_already_root_setid (runtime-security noise)
--
-- Demo host, 2026-10-17: logrotate (run nightly as root by logrotate.timer)
-- opened a HIGH incident "setgid(0) requested" every night. The kernel rates
-- setuid(0) CRITICAL and setgid(0) HIGH whenever the target differs from the
-- current effective ID, and ingest opens an incident for any stored event at
-- HIGH or above; logrotate sets its effective IDs aside for a "su" rotation
-- and takes them back afterwards.
-- New built-in (priority 46, after every other credential built-in) keeps
-- setuid(0)/setgid(0) at MEDIUM (stored, below the incident threshold; not
-- tagged expected: a compromised euid-dropped root daemon regaining root
-- looks the same), tagged already-root + credential-change, when
-- the event's real UID (kernel-recorded, initial user namespace) is already
-- 0: such a request needs no privilege and gains nothing. No process name is
-- matched, so no unverified-identity tag; any other real UID (a user running
-- a set-user-ID root binary, root of a user namespace) keeps its severity.
-- The flag a user can edit on a built-in is never written; new rows take the
-- column default (on). Custom rules are not touched. Hosts seeded after this
-- migration get the same rule from builtinRules (trace_rules_builtin.go).

INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade already-root credential change', 'A process whose real user ID is already 0 asking for user or group ID 0 (setuid(0), setgid(0)) gains no privilege: it is root and takes back IDs it set aside, as logrotate does after running a rotation as another user. Kept at MEDIUM (stored, no incident) and tagged; it is not marked expected because a compromised root daemon that dropped its effective IDs does the same. The match uses kernel-recorded IDs, not the process name, and a request by any other real user ID keeps its severity.', true, 'downgrade', '[{"field":"event_name","op":"in","value":["setuid","setgid"]},{"field":"detail","op":"eq","value":0},{"field":"uid","op":"eq","value":0}]'::jsonb, 2, 46, ARRAY(SELECT jsonb_array_elements_text('["already-root","credential-change"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade already-root credential change' AND r.built_in);
