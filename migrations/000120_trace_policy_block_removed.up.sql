-- The Runtime Security policy action "block" is gone. It relied on a BPF-LSM
-- connect blocklist that no install ever enabled, so a block policy never
-- denied anything. Outbound traffic to an address is blocked by the firewall
-- egress blocklist; a process is stopped by the action kill.
--
-- A stored block policy becomes an alert policy, so it keeps reporting the
-- events it matched. enabled is left as it is. The kernel flags are cleared:
-- they said the rule was enforced in the kernel, which it never was and an
-- alert policy is not.
--
-- The API refuses action block from this migration on, and the control plane
-- never sends it to an agent. Stored events and enforcement log rows are not
-- touched: their action names stay as recorded.
--
-- No other table holds a policy action. ebpf_trace_policies.action has no
-- CHECK constraint or enum.
UPDATE ebpf_trace_policies
   SET action                   = 'alert',
       kernel_enforce           = FALSE,
       kernel_enforce_requested = FALSE,
       auto_downgraded          = FALSE,
       enforcement_mode         = 'userspace',
       updated_at               = NOW()
 WHERE lower(action) = 'block';
