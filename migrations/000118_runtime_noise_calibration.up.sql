-- 000118_runtime_noise_calibration (runtime-security noise)
--
-- Preview control plane, 2026-11-16: a host agent on an ordinary Ubuntu 24.04
-- workstation (kernel 6.17) stored these in 15 minutes.
--
-- * Every sudo and cron run: a CRITICAL read of /etc/shadow. sudo is
--   set-user-ID, so the event carries the caller's real UID, and the process x
--   file matrix rates a credential file CRITICAL for any real UID but 0.
-- * A desktop tool running ps e four times a second: 700,000 HIGH reads of
--   /proc/<pid>/environ.
-- * One docker run: HIGH mounts by runc (its own /proc descriptors, the masked
--   and read-only /proc paths, the container state under /var/lib/docker),
--   HIGH chowns to root by dockerd, and a HIGH BPF program load by runc (the
--   device cgroup filter).
-- * ping: HIGH, because the kernel rates every raw socket outside AF_NETLINK
--   HIGH and ping sends ICMP through one.
--
-- Fifteen new built-ins (priorities 47-61), all downgrades. A process chooses
-- its own name, so they go to MEDIUM (stored, below the incident threshold)
-- and are tagged unverified-identity. The exceptions are a chown, chmod or mount by
-- dockerd or containerd under their own state directories that the kernel saw in
-- the agent-verified protected set: LOW. containerd unpacking image layers
-- (chmod and overlay mounts under /var/lib/containerd) was HIGH as well.
-- Each rule keeps the attacker variant loud: a write, an open the agent
-- reports as failed (ret_val below 0), any other name, any other parent and
-- any path outside the runtime's own directories keep their severity, so a
-- host path mounted into a container (/, /etc) still looks like the escape it
-- can be. They use two additions to the rule language that ship with this
-- release: the field ret_val and the operator starts_with_any (a list of path
-- prefixes).
-- A program reading the credential file of its own tool in a user's home
-- directory (ssh and ~/.ssh/id_ed25519, docker and ~/.docker/config.json) is
-- calibrated in the classifier (shared/tracefilter), not by a rule here.
-- Existing built-in rows are not touched. The flag a user can edit on a
-- built-in and the row IDs are never written; new rows take the column default
-- (on). Custom rules are not touched. Hosts seeded after this migration get
-- the same rules from builtinRules (trace_rules_builtin.go).

INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade auth helper shadow reads', 'sudo, su, cron and the other privilege and scheduler helpers read /etc/shadow and /etc/gshadow through PAM on every use. They run set-user-ID root or as root, and the event carries the real UID, so the matrix rates them CRITICAL. The helpers are exec''d and cannot be verified: a read-only open that the agent did not report as failed is kept at MEDIUM and tagged. Any other reader, a write and a failed open keep their severity.', true, 'downgrade', '[{"field":"comm","op":"in","value":["sudo","sudoedit","su","runuser","doas","pkexec","cron","crond","atd","login"]},{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"in","value":["/etc/shadow","/etc/gshadow"]},{"field":"ret_val","op":"gte","value":0},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb, 2, 47, ARRAY(SELECT jsonb_array_elements_text('["auth","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade auth helper shadow reads' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade process viewer environment reads', 'ps, top, htop and the other process viewers read /proc/<pid>/environ of every process they list (ps e, top -e, pgrep -f), and a desktop tool runs them several times a second. Read-only opens by these names are kept at MEDIUM and tagged; any other reader of a process environment and any write keeps its severity.', true, 'downgrade', '[{"field":"comm","op":"in","value":["ps","top","htop","btop","pgrep","pkill","pidof","procs","glances","systemd-cgls"]},{"field":"event_name","op":"eq","value":"openat"},{"field":"filename","op":"glob","value":"/proc/*/environ"},{"field":"event_name","op":"eq","value":"openat"},{"field":"flags","op":"bit_none","value":579}]'::jsonb, 2, 48, ARRAY(SELECT jsonb_array_elements_text('["proc","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade process viewer environment reads' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade container runtime setup mounts', 'runc builds a container''s filesystem with mounts of its own proc descriptors, the masked and read-only /proc paths and files under /var/lib/docker, /var/lib/containerd and /run/containerd. Kept at MEDIUM and tagged, only for runc or its init process under runc or a containerd shim. A host path mounted into a container (/, /etc) and the same mounts from any other parent keep their severity.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"mount"},{"field":"comm","op":"in","value":["runc","runc:[2:INIT]"]},{"field":"parent_comm","op":"in","value":["runc","containerd-shim","containerd-shim-runc-v2"]},{"field":"filename","op":"starts_with_any","value":["/proc/thread-self/","/proc/self/fd/","/proc/irq","/proc/bus","/proc/fs","/proc/sys","/proc/sysrq-trigger","/proc/kcore","/proc/keys","/proc/timer_list","/proc/acpi","/proc/scsi","/var/lib/docker/","/var/lib/containerd/","/run/containerd/"]}]'::jsonb, 2, 49, ARRAY(SELECT jsonb_array_elements_text('["container","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade container runtime setup mounts' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade verified container daemon chown', 'dockerd and containerd set root ownership on the container state they keep under /var/lib/docker and /var/lib/containerd. Changing a file''s owner to root needs root already. Only for a process the kernel saw in the agent-verified protected set; a process merely named dockerd keeps HIGH.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"chown"},{"field":"comm","op":"in","value":["dockerd","containerd"]},{"field":"detail","op":"eq","value":0},{"field":"filename","op":"starts_with_any","value":["/var/lib/docker/","/var/lib/containerd/"]},{"field":"exe_verified","op":"eq","value":true}]'::jsonb, 1, 50, ARRAY(SELECT jsonb_array_elements_text('["container","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade verified container daemon chown' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade container daemon chown', 'dockerd and containerd set root ownership on the container state they keep under /var/lib/docker and /var/lib/containerd. When the kernel did not mark the process verified the event is kept at MEDIUM and tagged, only for a chown to root under those two directories.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"chown"},{"field":"comm","op":"in","value":["dockerd","containerd"]},{"field":"detail","op":"eq","value":0},{"field":"filename","op":"starts_with_any","value":["/var/lib/docker/","/var/lib/containerd/"]}]'::jsonb, 2, 51, ARRAY(SELECT jsonb_array_elements_text('["container","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade container daemon chown' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade runc cgroup device BPF program', 'runc loads the BPF program that enforces a container''s device cgroup rules each time it starts a container. Kept at MEDIUM and tagged, only for runc under a containerd shim; BPF activity from any other process or parent keeps its severity.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"bpf"},{"field":"comm","op":"eq","value":"runc"},{"field":"parent_comm","op":"in","value":["containerd-shim","containerd-shim-runc-v2"]}]'::jsonb, 2, 52, ARRAY(SELECT jsonb_array_elements_text('["container","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade runc cgroup device BPF program' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade ICMP raw socket by network tools', 'ping, traceroute and mtr send ICMP through a raw socket, which the kernel rates HIGH for every process outside AF_NETLINK. Kept at MEDIUM and tagged, only for those names and the ICMP, ICMPv6 and raw IP protocols; a raw socket of any other protocol or name keeps its severity.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"socket"},{"field":"comm","op":"in","value":["ping","ping6","traceroute","mtr","mtr-packet"]},{"field":"addr_family","op":"in","value":[2,10]},{"field":"detail","op":"in","value":[3,2051,524291,526339]},{"field":"flags","op":"in","value":[1,58,255]}]'::jsonb, 2, 53, ARRAY(SELECT jsonb_array_elements_text('["network","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade ICMP raw socket by network tools' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade arping raw packet socket', 'arping sends ARP requests through a raw packet socket (AF_PACKET), which the kernel rates HIGH for every process outside AF_NETLINK. Kept at MEDIUM and tagged, only for that name; any other raw socket keeps its severity.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"socket"},{"field":"comm","op":"eq","value":"arping"},{"field":"addr_family","op":"eq","value":17},{"field":"detail","op":"in","value":[3,2051,524291,526339]}]'::jsonb, 2, 54, ARRAY(SELECT jsonb_array_elements_text('["network","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade arping raw packet socket' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade verified container daemon state changes', 'containerd and dockerd unpack image layers and mount container filesystems under /var/lib/containerd and /var/lib/docker, setting modes and mounting overlay layers there. Only for a process the kernel saw in the agent-verified protected set; a process merely named containerd keeps HIGH.', true, 'downgrade', '[{"field":"event_name","op":"in","value":["chmod","mount"]},{"field":"comm","op":"in","value":["dockerd","containerd"]},{"field":"filename","op":"starts_with_any","value":["/var/lib/docker/","/var/lib/containerd/"]},{"field":"exe_verified","op":"eq","value":true}]'::jsonb, 1, 55, ARRAY(SELECT jsonb_array_elements_text('["container","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade verified container daemon state changes' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade container daemon state changes', 'containerd and dockerd unpack image layers and mount container filesystems under /var/lib/containerd and /var/lib/docker. When the kernel did not mark the process verified the event is kept at MEDIUM and tagged, only under those two directories.', true, 'downgrade', '[{"field":"event_name","op":"in","value":["chmod","mount"]},{"field":"comm","op":"in","value":["dockerd","containerd"]},{"field":"filename","op":"starts_with_any","value":["/var/lib/docker/","/var/lib/containerd/"]}]'::jsonb, 2, 56, ARRAY(SELECT jsonb_array_elements_text('["container","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade container daemon state changes' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade container runtime pseudo-filesystem mounts', 'runc gives a new container its tmpfs, proc, sysfs, devpts, mqueue and cgroup filesystems and changes mount propagation, mounts that name a filesystem type or nothing as their source and so expose no host file. Kept at MEDIUM and tagged, only for runc or its init process under runc or a containerd shim. A mount whose source is a host path or a device keeps its severity.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"mount"},{"field":"comm","op":"in","value":["runc","runc:[2:INIT]"]},{"field":"parent_comm","op":"in","value":["runc","containerd-shim","containerd-shim-runc-v2"]},{"field":"filename","op":"in","value":["","tmpfs","proc","sysfs","devpts","mqueue","cgroup","cgroup2","shm","overlay","none"]}]'::jsonb, 2, 57, ARRAY(SELECT jsonb_array_elements_text('["container","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade container runtime pseudo-filesystem mounts' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade container init chown', 'runc''s init process sets root ownership on the console and the files it prepares inside the new container before it starts the workload. Kept at MEDIUM and tagged, only for a chown to root by runc:[2:INIT] under runc; any other name or parent keeps its severity.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"chown"},{"field":"comm","op":"eq","value":"runc:[2:INIT]"},{"field":"parent_comm","op":"eq","value":"runc"},{"field":"detail","op":"eq","value":0}]'::jsonb, 2, 58, ARRAY(SELECT jsonb_array_elements_text('["container","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade container init chown' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade verified container daemon overlay and namespace mounts', 'dockerd and containerd mount the overlay filesystem of a container and bind its namespace files from /proc (the network namespace under /run/docker/netns). Only for a process the kernel saw in the agent-verified protected set; a process merely named dockerd keeps HIGH.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"mount"},{"field":"comm","op":"in","value":["dockerd","containerd"]},{"field":"filename","op":"starts_with_any","value":["overlay","/proc/"]},{"field":"exe_verified","op":"eq","value":true}]'::jsonb, 1, 59, ARRAY(SELECT jsonb_array_elements_text('["container","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade verified container daemon overlay and namespace mounts' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade container daemon overlay and namespace mounts', 'dockerd and containerd mount the overlay filesystem of a container and bind its namespace files from /proc. When the kernel did not mark the process verified the event is kept at MEDIUM and tagged.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"mount"},{"field":"comm","op":"in","value":["dockerd","containerd"]},{"field":"filename","op":"starts_with_any","value":["overlay","/proc/"]}]'::jsonb, 2, 60, ARRAY(SELECT jsonb_array_elements_text('["container","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade container daemon overlay and namespace mounts' AND r.built_in);
INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade runc state directory chown', 'runc sets root ownership on the state directory it keeps for each container under /run/docker/runtime-runc, /run/containerd and /run/runc. Kept at MEDIUM and tagged, only for a chown to root there by runc under a containerd shim; any other path, name or parent keeps its severity.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"chown"},{"field":"comm","op":"eq","value":"runc"},{"field":"parent_comm","op":"in","value":["containerd-shim","containerd-shim-runc-v2"]},{"field":"detail","op":"eq","value":0},{"field":"filename","op":"starts_with_any","value":["/run/docker/runtime-runc/","/var/run/docker/runtime-runc/","/run/containerd/","/var/run/containerd/","/run/runc/","/var/run/runc/"]}]'::jsonb, 2, 61, ARRAY(SELECT jsonb_array_elements_text('["container","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade runc state directory chown' AND r.built_in);
