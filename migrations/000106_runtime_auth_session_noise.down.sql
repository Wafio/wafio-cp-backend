-- Reverse 000106: the /etc/shadow escalation matches on the filename alone
-- again, and the auth-session built-ins 000106 added are removed. The flag a
-- user can edit on the remaining rows is never written.

UPDATE trace_detection_rules SET conditions = '[{"field":"filename","op":"eq","value":"/etc/shadow"},{"field":"comm","op":"not_in","value":["sshd","sshd-session","sshd-auth","login","passwd","chage","useradd","usermod","pg_isready","postgres","shadow","unix_chkpwd","ansible","chef-client","puppet","osqueryi","aide","tripwire","restic","borg","bacula-fd","urbackupclient","backuppc"]}]'::jsonb, updated_at = NOW() WHERE built_in = true AND name = 'Escalate /etc/shadow read by unknown process';
DELETE FROM trace_detection_rules WHERE built_in = true AND name IN (
  'Downgrade verified auth daemon credential change',
  'Downgrade auth helper group change',
  'Downgrade verified auth daemon account database reads',
  'Downgrade unix_chkpwd shadow read under an auth parent',
  'Downgrade verified systemd BPF programs',
  'Downgrade systemd user-session setup shadow read',
  'Downgrade systemd user manager BPF programs',
  'Downgrade systemd-user-runtime-dir tmpfs mount',
  'Downgrade root chown to root under /usr',
  'Downgrade root chown to root under /opt'
);
