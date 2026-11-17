package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

// HostFleetRepo serves the Hosts fleet view and the multi-host apply target
// resolution. Every query filters
// project_id; agents are live rows only (deleted_at IS NULL) and
// incidents reach hosts only through agents of the same project.
type HostFleetRepo struct{ pool *pgxpool.Pool }

var _ domain.HostFleetStore = (*HostFleetRepo)(nil)

// FleetHostsPage returns one page of the project's hosts and their total.
func (r *HostFleetRepo) FleetHostsPage(ctx context.Context, projectID, hostID string, limit, offset int) ([]domain.FleetHostRow, int, error) {
	var hostArg any
	if hostID != "" {
		hostArg = hostID
	}
	var total int
	if err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM hosts WHERE project_id = $1 AND ($2::uuid IS NULL OR id = $2::uuid)`,
		projectID, hostArg).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("fleet count: %w", err)
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, name, COALESCE(labels,'{}'::jsonb), status, host_key_prefix,
		       COALESCE(host_info->>'hostname',''), COALESCE(host_os,''), COALESCE(host_os_version,''),
		       COALESCE(host_kernel,''), COALESCE(host_arch,''), last_seen, created_at, revoked_at
		  FROM hosts
		 WHERE project_id = $1 AND ($2::uuid IS NULL OR id = $2::uuid)
		 ORDER BY created_at DESC, id
		 LIMIT $3 OFFSET $4`, projectID, hostArg, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("fleet hosts: %w", err)
	}
	defer rows.Close()
	out := []domain.FleetHostRow{}
	for rows.Next() {
		var h domain.FleetHostRow
		var labels []byte
		if err := rows.Scan(&h.ID, &h.Name, &labels, &h.Status, &h.HostKeyPrefix, &h.Hostname, &h.HostOS,
			&h.HostOSVersion, &h.HostKernel, &h.HostArch, &h.LastSeen, &h.CreatedAt, &h.RevokedAt); err != nil {
			return nil, 0, err
		}
		h.Labels = decodeLabels(labels)
		out = append(out, h)
	}
	return out, total, rows.Err()
}

// decodeLabels reads a labels object; anything else is no labels.
func decodeLabels(raw []byte) map[string]string {
	out := map[string]string{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	if out == nil {
		out = map[string]string{}
	}
	return out
}

// FleetAgents returns the live agents of the given hosts with their status
// fields projected in SQL (no status blobs leave the database).
func (r *HostFleetRepo) FleetAgents(ctx context.Context, projectID string, hostIDs []string) ([]domain.FleetAgentRow, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT a.id, a.host_id, a.kind, a.name, COALESCE(a.version,''), a.last_seen, a.last_state_at,
		       a.host_info->'firewall_features',
		       jsonb_typeof(s.e) = 'object',
		       jsonb_build_object(
		         'running', s.e->'running', 'xdp_attached', s.e->'xdp_attached',
		         'tc_egress_attached', s.e->'tc_egress_attached', 'xdp_mode', s.e->'xdp_mode',
		         'enabled', s.e#>'{config,global,enabled}', 'monitor_only', s.e#>'{config,global,monitor_only}',
		         'has_config', jsonb_typeof(s.e->'config') = 'object',
		         'lockout_exemptions', s.e->'lockout_exemptions',
		         'geo_degraded_code', s.e->'geo_degraded_code',
		         'allowlist_scoped_skipped', s.e->'allowlist_scoped_skipped',
		         'coverage_warnings', CASE WHEN jsonb_typeof(s.e->'coverage_warnings') = 'array'
		                                   THEN (SELECT count(*) FROM jsonb_array_elements_text(s.e->'coverage_warnings') w
		                                          WHERE NOT (w = ANY($3::text[]))) END),
		       jsonb_typeof(s.t) = 'object', s.t->'running',
		       CASE WHEN jsonb_typeof(s.t->'missing_probes') = 'object'
		            THEN (SELECT count(*) FROM jsonb_object_keys(s.t->'missing_probes')) END,
		       COALESCE(pc.enabled, 0), COALESCE(pc.enforcing, 0)
		  FROM agents a
		 CROSS JOIN LATERAL (SELECT a.last_status_json->'ebpf' AS e, a.last_status_json->'trace' AS t) s
		  LEFT JOIN LATERAL (
		       SELECT count(*) FILTER (WHERE p.enabled) AS enabled,
		              count(*) FILTER (WHERE p.enabled AND p.action IN ('kill','block')) AS enforcing
		         FROM ebpf_trace_policies p WHERE p.agent_id = a.id) pc ON a.kind = 'host'
		 WHERE a.project_id = $1 AND a.deleted_at IS NULL AND a.host_id = ANY($2::uuid[])`,
		projectID, hostIDs, hostpolicy.BaselineCoverageNotes)
	if err != nil {
		return nil, fmt.Errorf("fleet agents: %w", err)
	}
	defer rows.Close()
	out := []domain.FleetAgentRow{}
	for rows.Next() {
		var (
			a                  domain.FleetAgentRow
			features, ebpfJSON []byte
			traceRunning       []byte
			hasEBPF, hasTrace  *bool
			missing            *int64
			enabled, enforcing int64
		)
		if err := rows.Scan(&a.ID, &a.HostID, &a.Kind, &a.Name, &a.Version, &a.LastSeen, &a.LastStateAt,
			&features, &hasEBPF, &ebpfJSON, &hasTrace, &traceRunning, &missing, &enabled, &enforcing); err != nil {
			return nil, err
		}
		a.HasEBPF = hasEBPF != nil && *hasEBPF
		a.HasTrace = hasTrace != nil && *hasTrace
		if len(features) > 0 {
			var f []string
			if json.Unmarshal(features, &f) == nil {
				a.FirewallFeatures = f
			}
		}
		if a.HasEBPF {
			a.EBPF = decodeFleetEBPF(ebpfJSON)
		}
		if len(traceRunning) > 0 {
			var b bool
			if json.Unmarshal(traceRunning, &b) == nil {
				a.TraceRunning = &b
			}
		}
		if missing != nil {
			n := int(*missing)
			a.MissingProbes = &n
		}
		a.EnabledPolicies, a.EnforcingPolicies = int(enabled), int(enforcing)
		out = append(out, a)
	}
	return out, rows.Err()
}

// decodeFleetEBPF reads the projected status object field by field, so one
// field of an unexpected type (an agent bug) leaves only that field unset.
func decodeFleetEBPF(raw []byte) domain.FleetEBPFStatus {
	var fields map[string]json.RawMessage
	var out domain.FleetEBPFStatus
	if json.Unmarshal(raw, &fields) != nil {
		return out
	}
	boolField := func(k string) *bool {
		var b bool
		if v, ok := fields[k]; ok && json.Unmarshal(v, &b) == nil && string(v) != "null" {
			return &b
		}
		return nil
	}
	strField := func(k string) *string {
		var s string
		if v, ok := fields[k]; ok && json.Unmarshal(v, &s) == nil && string(v) != "null" {
			return &s
		}
		return nil
	}
	intField := func(k string) *int {
		var n int
		if v, ok := fields[k]; ok && json.Unmarshal(v, &n) == nil && string(v) != "null" {
			return &n
		}
		return nil
	}
	out.Running = boolField("running")
	out.XDPAttached = boolField("xdp_attached")
	out.TCEgressAttached = boolField("tc_egress_attached")
	out.XDPMode = strField("xdp_mode")
	out.Enabled = boolField("enabled")
	out.MonitorOnly = boolField("monitor_only")
	out.HasConfig = boolField("has_config")
	out.LockoutExemptions = boolField("lockout_exemptions")
	out.GeoDegradedCode = strField("geo_degraded_code")
	out.AllowlistScopedSkipped = intField("allowlist_scoped_skipped")
	out.CoverageWarnings = intField("coverage_warnings")
	return out
}

// FleetIncidentCounts counts the open/acknowledged critical and high
// incident groups of the given hosts.
func (r *HostFleetRepo) FleetIncidentCounts(ctx context.Context, projectID string, hostIDs []string) (map[string]domain.HostIncidentCounts, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT a.host_id,
		       count(*) FILTER (WHERE hi.status = 'open' AND hi.severity_name = 'critical'),
		       count(*) FILTER (WHERE hi.status = 'open' AND hi.severity_name = 'high'),
		       count(*) FILTER (WHERE hi.status = 'acknowledged')
		  FROM host_incidents hi
		  JOIN agents a ON a.id::text = hi.agent_id AND a.project_id = hi.project_id AND a.deleted_at IS NULL
		 WHERE hi.project_id = $1 AND hi.status IN ('open','acknowledged')
		   AND hi.severity_name IN ('critical','high') AND a.host_id = ANY($2::uuid[])
		 GROUP BY a.host_id`, projectID, hostIDs)
	if err != nil {
		return nil, fmt.Errorf("fleet incidents: %w", err)
	}
	defer rows.Close()
	out := map[string]domain.HostIncidentCounts{}
	for rows.Next() {
		var hostID string
		var crit, high, ack int64
		if err := rows.Scan(&hostID, &crit, &high, &ack); err != nil {
			return nil, err
		}
		out[hostID] = domain.HostIncidentCounts{OpenCritical: int(crit), OpenHigh: int(high), Acknowledged: int(ack)}
	}
	return out, rows.Err()
}

// CountUnlinkedHostAgents counts the project's live host agents without a
// host (started without --host-key).
func (r *HostFleetRepo) CountUnlinkedHostAgents(ctx context.Context, projectID string) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM agents WHERE project_id = $1 AND deleted_at IS NULL AND kind = 'host' AND host_id IS NULL`,
		projectID).Scan(&n)
	return n, err
}

// applyTargetsSelect resolves hosts with their newest live host agent.
const applyTargetsSelect = `
	SELECT h.id, h.name, (h.revoked_at IS NOT NULL OR h.status = 'revoked'),
	       ag.id, ag.last_seen, ag.ssh_ports, ag.features, COALESCE(ag.egress_v6, false)
	  FROM hosts h
	  LEFT JOIN LATERAL (
	       SELECT a.id, a.last_seen, a.host_info->'ssh_ports' AS ssh_ports,
	              a.host_info->'firewall_features' AS features,
	              CASE WHEN jsonb_typeof(a.last_status_json#>'{ebpf,egress_ipv6_supported}') = 'boolean'
	                   THEN (a.last_status_json#>>'{ebpf,egress_ipv6_supported}')::boolean END AS egress_v6
	         FROM agents a
	        WHERE a.host_id = h.id AND a.project_id = h.project_id AND a.deleted_at IS NULL AND a.kind = 'host'
	        ORDER BY a.last_seen DESC NULLS LAST, a.created_at DESC
	        LIMIT 1) ag ON true
	 WHERE h.project_id = $1 `

// ApplyTargets resolves the hosts of an apply (see domain.HostFleetStore).
func (r *HostFleetRepo) ApplyTargets(ctx context.Context, projectID string, hostIDs []string, label *domain.LabelSelector, limit int) ([]domain.ApplyTarget, int, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if label != nil {
		var matched int
		if err := r.pool.QueryRow(ctx, `
			SELECT count(*) FROM hosts
			 WHERE project_id = $1 AND revoked_at IS NULL AND status <> 'revoked'
			   AND COALESCE(labels,'{}'::jsonb) @> jsonb_build_object($2::text, $3::text)`,
			projectID, label.Key, label.Value).Scan(&matched); err != nil {
			return nil, 0, fmt.Errorf("apply targets count: %w", err)
		}
		if matched > limit || matched == 0 {
			return nil, matched, nil
		}
		rows, err = r.pool.Query(ctx, applyTargetsSelect+`
			   AND h.revoked_at IS NULL AND h.status <> 'revoked'
			   AND COALESCE(h.labels,'{}'::jsonb) @> jsonb_build_object($2::text, $3::text)
			 ORDER BY h.name, h.id`, projectID, label.Key, label.Value)
	} else {
		rows, err = r.pool.Query(ctx, applyTargetsSelect+`
			   AND h.id = ANY($2::uuid[])
			 ORDER BY h.name, h.id`, projectID, hostIDs)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("apply targets: %w", err)
	}
	defer rows.Close()
	out := []domain.ApplyTarget{}
	for rows.Next() {
		var (
			t               domain.ApplyTarget
			agentID         *string
			sshRaw, featRaw []byte
		)
		if err := rows.Scan(&t.HostID, &t.HostName, &t.Revoked, &agentID, &t.AgentLastSeen, &sshRaw, &featRaw, &t.EgressIPv6Supported); err != nil {
			return nil, 0, err
		}
		if agentID != nil {
			t.AgentID = *agentID
		}
		if len(sshRaw) > 0 && string(sshRaw) != "null" {
			var ports []uint16
			if json.Unmarshal(sshRaw, &ports) == nil {
				t.SSHPorts = ports
			}
		}
		if len(featRaw) > 0 && string(featRaw) != "null" {
			var f []string
			if json.Unmarshal(featRaw, &f) == nil {
				t.FirewallFeatures = f
			}
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, len(out), nil
}

// UpdateLabelsAudited edits host labels atomically (see
// domain.HostFleetStore): one transaction, rows locked in id order, one
// host.labels_updated audit row per changed host on the same transaction.
func (r *HostFleetRepo) UpdateLabelsAudited(ctx context.Context, projectID string, hostIDs []string,
	edit func(current []domain.HostLabels) ([]domain.HostLabels, error), actor domain.AuditActor, changeID string) ([]domain.HostLabels, int, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit
	rows, err := tx.Query(ctx, `
		SELECT id, name, COALESCE(labels,'{}'::jsonb) FROM hosts
		 WHERE project_id = $1 AND id = ANY($2::uuid[])
		 ORDER BY id FOR UPDATE`, projectID, hostIDs)
	if err != nil {
		return nil, 0, err
	}
	current := []domain.HostLabels{}
	for rows.Next() {
		var h domain.HostLabels
		var raw []byte
		if err := rows.Scan(&h.ID, &h.Name, &raw); err != nil {
			rows.Close()
			return nil, 0, err
		}
		h.Labels = decodeLabels(raw)
		current = append(current, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if len(current) != len(hostIDs) {
		return nil, 0, domain.ErrHostNotFound
	}
	before := make([]map[string]string, len(current))
	for i := range current {
		before[i] = maps.Clone(current[i].Labels)
	}
	next, err := edit(current)
	if err != nil {
		return nil, 0, err
	}
	if len(next) != len(current) {
		return nil, 0, errors.New("label edit returned a different host set")
	}
	updated := 0
	for i, h := range next {
		if h.ID != current[i].ID {
			return nil, 0, errors.New("label edit reordered hosts")
		}
		if maps.Equal(before[i], h.Labels) {
			continue
		}
		raw, err := json.Marshal(h.Labels)
		if err != nil {
			return nil, 0, err
		}
		if _, err := tx.Exec(ctx, `UPDATE hosts SET labels = $3::jsonb WHERE project_id = $1 AND id = $2`,
			projectID, h.ID, string(raw)); err != nil {
			return nil, 0, err
		}
		ev := AuditEvent{
			ProjectID: projectID, ActorUserID: actor.UserID,
			Action: AuditHostLabelsUpdated, TargetType: "host", TargetID: h.ID, TargetName: h.Name,
			IP: actor.IP, UserAgent: actor.UserAgent,
			MetadataJSON: map[string]any{"before": before[i], "after": h.Labels, "change_id": changeID},
		}
		if err := insertAudit(ctx, tx, ev); err != nil {
			return nil, 0, noteAuditFailure("agent_audit", ev.Action, err)
		}
		updated++
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, 0, err
	}
	return next, updated, nil
}
