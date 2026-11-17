-- 000100_clamp_port_scan_threshold (firewall gap analysis 2026-10-10)
--
-- The XDP port-scan detector tracks at most 32 distinct destination ports
-- per source (MAX_SCAN_PORTS, ebpf.MaxPortScanUniquePorts). The control plane
-- and the dashboard used to accept thresholds up to 128; the dataplane then
-- never detected a scan and logged every TCP packet of the source instead.
-- Saves now refuse anything above 32 (400 INVALID_CONFIG) and agents lower
-- it on delivery. This rewrites stored thresholds above 32 to 32 once, the
-- closest value the dataplane can enforce, and sets drop_on_detect to false:
-- such a threshold never dropped anything, and a host must not start dropping
-- on upgrade. The operator can turn dropping back on deliberately. Other
-- fields are kept.

UPDATE agents
SET desired_state = jsonb_set(
        jsonb_set(desired_state, '{config,port_scan,max_unique_ports}', '32'::jsonb),
        '{config,port_scan,drop_on_detect}', 'false'::jsonb)
WHERE jsonb_typeof(desired_state #> '{config,port_scan,max_unique_ports}') = 'number'
  AND (desired_state #>> '{config,port_scan,max_unique_ports}')::numeric > 32;
