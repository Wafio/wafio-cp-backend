-- Reverse 000118: remove the fifteen built-ins it added. The flag a user can edit
-- on the remaining rows is never written.

DELETE FROM trace_detection_rules WHERE built_in = true AND name IN (
  'Downgrade auth helper shadow reads',
  'Downgrade process viewer environment reads',
  'Downgrade container runtime setup mounts',
  'Downgrade verified container daemon chown',
  'Downgrade container daemon chown',
  'Downgrade runc cgroup device BPF program',
  'Downgrade ICMP raw socket by network tools',
  'Downgrade arping raw packet socket',
  'Downgrade verified container daemon state changes',
  'Downgrade container daemon state changes',
  'Downgrade container runtime pseudo-filesystem mounts',
  'Downgrade container init chown',
  'Downgrade verified container daemon overlay and namespace mounts',
  'Downgrade container daemon overlay and namespace mounts',
  'Downgrade runc state directory chown'
);
