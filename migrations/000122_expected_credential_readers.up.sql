-- 000122_expected_credential_readers (runtime-security noise)
--
-- A test host held 41 open incidents. Twenty of them came from services,
-- package runs and installers doing their job: nginx loading its TLS key,
-- systemd-networkd opening its sockets, debconf and needrestart reading the
-- account database and process environments, dracut and dpkg-deb setting
-- ownership, a directory listing of a key directory. The process x file matrix
-- rates a credential read CRITICAL for every real UID but 0 and for every name
-- it does not know, and the kernel rates a raw socket, a BPF load and a chown
-- to root HIGH.
--
-- Eleven new built-ins (priorities 63 to 73). All downgrade, so the event stays
-- stored and tagged and only the incident goes away. The open rules keep the
-- read-only guard.
--   63  nginx master (root, systemd parent, verified) reading its TLS key: LOW
--   64  nginx under certbot reading its key after a renewal: MEDIUM
--   65  systemd-networkd (verified, its own user) opening its raw ICMPv6
--       socket: LOW
--   66  systemd-networkd (verified, its own user) opening its raw LLDP packet
--       socket: LOW
--   67  debconf front end and dpkg-preconfigure reading /etc/shadow in a
--       package run: MEDIUM
--   68  grep under dracut reading /etc/shadow: MEDIUM
--   69  needrestart reading /proc/<pid>/environ: MEDIUM
--   70  sed under a needrestart hook reading /proc/<pid>/environ: MEDIUM
--   71  pg_ctlcluster reading /etc/shadow at boot: MEDIUM
--   72  tar under dpkg-deb setting root ownership: MEDIUM
--   73  cp under dracut setting root ownership: MEDIUM
-- A rule that names a process the agent cannot verify names root, the exact
-- process, its lineage and the file, and carries unverified-identity. Two
-- shapes stay incidents because nothing in the event tells the service from a
-- process that took its name: the PostgreSQL server key read (the postgres
-- account is not root and belongs to the ssl-cert group) and a BPF program
-- load by systemd-networkd (the verified mark is shared with the WAF agent
-- and every other protected process).
-- Six existing built-ins change, description and conditions only:
--   - the sshd host key rule also accepts a systemd parent (sshd at start);
--   - the PID 1 environment rule also names networkctl;
--   - the verified systemd BPF rule and the three verified container daemon
--     rules also need real UID 0, as the five rules of 000121 do. A verified
--     process is not always root, and systemd-networkd is now a second verified
--     process that is not.
-- The flag a user can edit on a built-in and the row IDs are never written;
-- the new rows take the column default (on). Custom rules are not touched.
-- Hosts seeded after this migration get the same rules from builtinRules
-- (trace_rules_builtin.go).

INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade verified web server TLS key reads', 'nginx loads its TLS keys under /etc/ssl/private and /etc/letsencrypt/live when the service starts, on a reload and on its configuration test, as root under systemd. Kept at LOW and tagged, only for a root process the agent verified as the nginx host binary, under a systemd parent, with an open that did not fail. A worker, an unverified process, a write, any other file and a failed open keep their severity.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"starts_with_any","value":["/etc/ssl/private/","/etc/letsencrypt/live/"]},{"field":"comm","op":"eq","value":"nginx"},{"field":"parent_comm","op":"eq","value":"systemd"},{"field":"uid","op":"eq","value":0},{"field":"exe_verified","op":"eq","value":true},{"field":"ret_val","op":"gte","value":0},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb, 1, 63, ARRAY(SELECT jsonb_array_elements_text('["web-server","tls","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade verified web server TLS key reads' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade web server key reads in certbot reloads', 'The nginx plugin of certbot runs nginx -t and nginx -s reload after it renews a certificate, and both read the key under /etc/letsencrypt/live. certbot starts them as new programs, so the agent cannot verify them: kept at MEDIUM and tagged, only for root, a certbot parent, a read-only open that did not fail. Any other parent, a worker, a write and a failed open keep their severity.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"starts_with","value":"/etc/letsencrypt/live/"},{"field":"comm","op":"eq","value":"nginx"},{"field":"parent_comm","op":"eq","value":"certbot"},{"field":"uid","op":"eq","value":0},{"field":"ret_val","op":"gte","value":0},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb, 2, 64, ARRAY(SELECT jsonb_array_elements_text('["web-server","tls","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade web server key reads in certbot reloads' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade verified systemd-networkd ICMPv6 raw socket', 'systemd-networkd runs as its own unprivileged user and opens a raw ICMPv6 socket for router discovery when it starts. Kept at LOW and tagged, only for a non-root process the agent verified as the systemd-networkd binary of its own unit, and only for that socket (AF_INET6, SOCK_RAW, protocol 58). An unverified process with that name, root, any other socket and a BPF program load keep their severity.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"socket"},{"field":"comm","op":"eq","value":"systemd-network"},{"field":"uid","op":"neq","value":0},{"field":"exe_verified","op":"eq","value":true},{"field":"addr_family","op":"eq","value":10},{"field":"detail","op":"in","value":[3,2051,524291,526339]},{"field":"flags","op":"eq","value":58}]'::jsonb, 1, 65, ARRAY(SELECT jsonb_array_elements_text('["systemd","network","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade verified systemd-networkd ICMPv6 raw socket' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade verified systemd-networkd LLDP packet socket', 'systemd-networkd runs as its own unprivileged user and opens a raw packet socket for LLDP when it starts. Kept at LOW and tagged, only for a non-root process the agent verified as the systemd-networkd binary of its own unit, and only for that socket (AF_PACKET, SOCK_RAW, EtherType 0x88CC). An unverified process with that name, root, any other socket and a BPF program load keep their severity.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"socket"},{"field":"comm","op":"eq","value":"systemd-network"},{"field":"uid","op":"neq","value":0},{"field":"exe_verified","op":"eq","value":true},{"field":"addr_family","op":"eq","value":17},{"field":"detail","op":"in","value":[3,2051,524291,526339]},{"field":"flags","op":"eq","value":52360}]'::jsonb, 1, 66, ARRAY(SELECT jsonb_array_elements_text('["systemd","network","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade verified systemd-networkd LLDP packet socket' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade debconf account database reads in package runs', 'The debconf front end (frontend) and dpkg-preconfigure run Perl as root during a package run, and Perl reads /etc/shadow when it looks up an account. Kept at MEDIUM and tagged, only for root, a read-only open that did not fail and an apt, dpkg or unattended-upgrades grandparent. Any other lineage, user or reader keeps its severity.', true, 'downgrade', '[{"field":"comm","op":"in","value":["dpkg-preconfigu","frontend"]},{"field":"grandparent_comm","op":"in","value":["unattended-upgr","apt-get","apt","aptitude","dpkg"]},{"field":"uid","op":"eq","value":0},{"field":"filename","op":"eq","value":"/etc/shadow"},{"field":"ret_val","op":"gte","value":0},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb, 2, 67, ARRAY(SELECT jsonb_array_elements_text('["package-manager","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade debconf account database reads in package runs' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade dracut root account read', 'dracut runs grep over /etc/shadow as root when it builds an initramfs. Kept at MEDIUM and tagged, only for root, a dracut parent, a read-only open that did not fail. Any other parent, user or reader keeps its severity.', true, 'downgrade', '[{"field":"comm","op":"eq","value":"grep"},{"field":"parent_comm","op":"eq","value":"dracut"},{"field":"uid","op":"eq","value":0},{"field":"filename","op":"eq","value":"/etc/shadow"},{"field":"ret_val","op":"gte","value":0},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb, 2, 68, ARRAY(SELECT jsonb_array_elements_text('["initramfs","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade dracut root account read' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade needrestart process environment reads', 'needrestart reads /proc/<pid>/environ of the services it checks after a package run. Most of these opens fail because the process has exited. Kept at MEDIUM and tagged, only for root and a read-only open; any other reader of a process environment keeps its severity.', true, 'downgrade', '[{"field":"comm","op":"eq","value":"needrestart"},{"field":"uid","op":"eq","value":0},{"field":"filename","op":"glob","value":"/proc/*/environ"},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb, 2, 69, ARRAY(SELECT jsonb_array_elements_text('["package-manager","proc","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade needrestart process environment reads' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade needrestart hook environment reads', 'A needrestart hook runs sed over /proc/<pid>/environ of the services it checks. Kept at MEDIUM and tagged, only for root, a read-only open and needrestart as the grandparent of sed; any other reader of a process environment keeps its severity.', true, 'downgrade', '[{"field":"comm","op":"eq","value":"sed"},{"field":"grandparent_comm","op":"eq","value":"needrestart"},{"field":"uid","op":"eq","value":0},{"field":"filename","op":"glob","value":"/proc/*/environ"},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb, 2, 70, ARRAY(SELECT jsonb_array_elements_text('["package-manager","proc","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade needrestart hook environment reads' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade pg_ctlcluster account database read at start', 'pg_ctlcluster, which systemd starts at boot to bring up a PostgreSQL cluster, reads /etc/shadow as root. Kept at MEDIUM and tagged, only for root, a systemd parent started by the kernel, a read-only open that did not fail. Any other lineage, user or reader keeps its severity.', true, 'downgrade', '[{"field":"comm","op":"eq","value":"pg_ctlcluster"},{"field":"parent_comm","op":"eq","value":"systemd"},{"field":"grandparent_comm","op":"eq","value":"swapper/0"},{"field":"uid","op":"eq","value":0},{"field":"filename","op":"eq","value":"/etc/shadow"},{"field":"ret_val","op":"gte","value":0},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb, 2, 71, ARRAY(SELECT jsonb_array_elements_text('["postgresql","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade pg_ctlcluster account database read at start' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade dpkg-deb control extraction chown', 'dpkg-deb runs tar as root to unpack the control files of a package, and tar sets root ownership on the directory. Kept at MEDIUM and tagged, only for a chown to root by tar under dpkg-deb, on the working directory or /var/lib/dpkg/tmp.ci. Any other path, parent or user keeps its severity.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"chown"},{"field":"detail","op":"eq","value":0},{"field":"uid","op":"eq","value":0},{"field":"comm","op":"eq","value":"tar"},{"field":"parent_comm","op":"eq","value":"dpkg-deb"},{"field":"filename","op":"in","value":[".","/var/lib/dpkg/tmp.ci"]}]'::jsonb, 2, 72, ARRAY(SELECT jsonb_array_elements_text('["package-manager","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade dpkg-deb control extraction chown' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade dracut initramfs copy chown', 'dracut copies files into the initramfs it builds and cp sets root ownership on them. Kept at MEDIUM and tagged, only for a chown to root by cp under dracut. Any other parent or user keeps its severity.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"chown"},{"field":"detail","op":"eq","value":0},{"field":"uid","op":"eq","value":0},{"field":"comm","op":"eq","value":"cp"},{"field":"parent_comm","op":"eq","value":"dracut"}]'::jsonb, 2, 73, ARRAY(SELECT jsonb_array_elements_text('["initramfs","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade dracut initramfs copy chown' AND r.built_in);
UPDATE trace_detection_rules SET description = 'sshd loads its own host keys on every connection and when it starts. Reading /etc/ssh/* is the daemon doing its job. Only for a root process the agent verified as the sshd host binary, under an sshd or a systemd parent.', conditions = '[{"field":"comm","op":"eq","value":"sshd"},{"field":"parent_comm","op":"in","value":["sshd","systemd"]},{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"starts_with","value":"/etc/ssh/"},{"field":"uid","op":"eq","value":0},{"field":"exe_verified","op":"eq","value":true},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb WHERE built_in = true AND name = 'Downgrade sshd host key reads';
UPDATE trace_detection_rules SET description = 'systemctl, networkctl, the systemd environment generator, needrestart and cloud-id read PID 1''s environment (/proc/1/environ) at login, motd refresh, package runs or when networkd starts. Read-only opens by these names are kept at MEDIUM and tagged; any other reader keeps its severity.', conditions = '[{"field":"comm","op":"in","value":["systemctl","30-systemd-envi","needrestart","cloud-id","systemd-detect-","networkctl"]},{"field":"filename","op":"eq","value":"/proc/1/environ"},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb WHERE built_in = true AND name = 'Downgrade PID 1 environment reads by system tools';
UPDATE trace_detection_rules SET description = 'systemd (PID 1) loads cgroup BPF programs (device policy, IP accounting and firewalling) whenever it starts a unit, including every user session. Only for a root process the kernel saw as PID 1 or in the agent-verified protected set.', conditions = '[{"field":"comm","op":"eq","value":"systemd"},{"field":"event_name","op":"eq","value":"bpf"},{"field":"uid","op":"eq","value":0},{"field":"exe_verified","op":"eq","value":true}]'::jsonb WHERE built_in = true AND name = 'Downgrade verified systemd BPF programs';
UPDATE trace_detection_rules SET description = 'dockerd and containerd set root ownership on the container state they keep under /var/lib/docker and /var/lib/containerd. Changing a file''s owner to root needs root already. Only for a root process the kernel saw in the agent-verified protected set; a process merely named dockerd keeps HIGH.', conditions = '[{"field":"event_name","op":"eq","value":"chown"},{"field":"comm","op":"in","value":["dockerd","containerd"]},{"field":"detail","op":"eq","value":0},{"field":"filename","op":"starts_with_any","value":["/var/lib/docker/","/var/lib/containerd/"]},{"field":"uid","op":"eq","value":0},{"field":"exe_verified","op":"eq","value":true}]'::jsonb WHERE built_in = true AND name = 'Downgrade verified container daemon chown';
UPDATE trace_detection_rules SET description = 'containerd and dockerd unpack image layers and mount container filesystems under /var/lib/containerd and /var/lib/docker, setting modes and mounting overlay layers there. Only for a root process the kernel saw in the agent-verified protected set; a process merely named containerd keeps HIGH.', conditions = '[{"field":"event_name","op":"in","value":["chmod","mount"]},{"field":"comm","op":"in","value":["dockerd","containerd"]},{"field":"filename","op":"starts_with_any","value":["/var/lib/docker/","/var/lib/containerd/"]},{"field":"uid","op":"eq","value":0},{"field":"exe_verified","op":"eq","value":true}]'::jsonb WHERE built_in = true AND name = 'Downgrade verified container daemon state changes';
UPDATE trace_detection_rules SET description = 'dockerd and containerd mount the overlay filesystem of a container and bind its namespace files from /proc (the network namespace under /run/docker/netns). Only for a root process the kernel saw in the agent-verified protected set; a process merely named dockerd keeps HIGH.', conditions = '[{"field":"event_name","op":"eq","value":"mount"},{"field":"comm","op":"in","value":["dockerd","containerd"]},{"field":"filename","op":"starts_with_any","value":["overlay","/proc/"]},{"field":"uid","op":"eq","value":0},{"field":"exe_verified","op":"eq","value":true}]'::jsonb WHERE built_in = true AND name = 'Downgrade verified container daemon overlay and namespace mounts';
