-- Rollback: restore the original (legacy "sshd"-only) built-in rule conditions.

UPDATE trace_detection_rules
SET conditions = '[{"field":"event_name","op":"eq","value":"setuid"},{"field":"comm","op":"not_in","value":["sshd","su","sudo","login","passwd","newgrp","runc","runc:[2:INIT]","containerd-shim","containerd","dockerd","kubelet","cron","crond","at","systemd"]}]'::jsonb,
    updated_at = NOW()
WHERE built_in AND name = 'Escalate unknown binary setuid';

UPDATE trace_detection_rules
SET conditions = '[{"field":"filename","op":"contains","value":"/etc/shadow"},{"field":"comm","op":"not_in","value":["sshd","login","passwd","chage","useradd","usermod","pg_isready","postgres","shadow","unix_chkpwd"]}]'::jsonb,
    updated_at = NOW()
WHERE built_in AND name = 'Escalate /etc/shadow read by unknown process';

UPDATE trace_detection_rules
SET conditions = '[{"field":"comm","op":"eq","value":"sshd"},{"field":"event_name","op":"eq","value":"setuid"}]'::jsonb,
    updated_at = NOW()
WHERE built_in AND name = 'Suppress sshd setuid during normal auth';
