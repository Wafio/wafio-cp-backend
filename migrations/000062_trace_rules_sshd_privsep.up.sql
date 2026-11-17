-- 000062_trace_rules_sshd_privsep
-- Fix false-positive CRITICAL events caused by OpenSSH ≥9.x privilege separation.
-- Modern sshd runs as "sshd-session" / "sshd-auth", but the built-in trace
-- detection rules only matched the legacy monolithic "sshd" comm. As a result:
--   • sshd-session reading /etc/shadow / authorized_keys was escalated to CRITICAL
--   • sshd-session / sshd-auth setuid(0) was escalated to CRITICAL
--   • the "Suppress sshd setuid" rule never matched (comm eq "sshd")
-- This UPDATEs the built-in rules in every project to recognize the
-- privilege-separated process names. Classifier-side fixes (process group +
-- known-privilege-binary setuid downgrade) ship in the same release.
--
-- Built-in rules are immutable via the API, so their conditions equal the
-- originally seeded values and can be safely overwritten by name.

UPDATE trace_detection_rules
SET conditions = '[{"field":"event_name","op":"eq","value":"setuid"},{"field":"comm","op":"not_in","value":["sshd","sshd-session","sshd-auth","su","sudo","login","passwd","newgrp","runc","runc:[2:INIT]","containerd-shim","containerd","dockerd","kubelet","cron","crond","at","systemd"]}]'::jsonb,
    updated_at = NOW()
WHERE built_in AND name = 'Escalate unknown binary setuid';

UPDATE trace_detection_rules
SET conditions = '[{"field":"filename","op":"contains","value":"/etc/shadow"},{"field":"comm","op":"not_in","value":["sshd","sshd-session","sshd-auth","login","passwd","chage","useradd","usermod","pg_isready","postgres","shadow","unix_chkpwd"]}]'::jsonb,
    updated_at = NOW()
WHERE built_in AND name = 'Escalate /etc/shadow read by unknown process';

UPDATE trace_detection_rules
SET conditions = '[{"field":"comm","op":"in","value":["sshd","sshd-session","sshd-auth"]},{"field":"event_name","op":"eq","value":"setuid"}]'::jsonb,
    updated_at = NOW()
WHERE built_in AND name = 'Suppress sshd setuid during normal auth';
