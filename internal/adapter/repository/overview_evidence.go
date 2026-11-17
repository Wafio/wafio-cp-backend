package repository

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/wafio/wafio-cp-backend/internal/dashboard"
)

// OverviewEvidence reads durable sources at one PostgreSQL snapshot. Connection
// ACKs are attached separately by delivery code and carry their own timestamp.
func (r *WAFRepo) OverviewEvidence(ctx context.Context, projectID, hostID string) (*dashboard.OverviewEvidence, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	result := &dashboard.OverviewEvidence{ProjectID: projectID, HostID: hostID, Sources: map[string]dashboard.EvidenceSource{}, Agents: []dashboard.AgentEvidence{}, Actions: []dashboard.OverviewAction{}}
	if err := tx.QueryRow(ctx, `SELECT transaction_timestamp() FROM projects WHERE id=$1`, projectID).Scan(&result.SnapshotAt); err != nil {
		return nil, err
	}
	result.SnapshotAt = result.SnapshotAt.UTC()
	if hostID != "" {
		var id string
		if err := tx.QueryRow(ctx, `SELECT id FROM hosts WHERE project_id=$1 AND id=$2`, projectID, hostID).Scan(&id); err != nil {
			return nil, err
		}
	}
	source := dashboard.EvidenceSource{State: "observed", ObservedAt: &result.SnapshotAt}
	rows, err := tx.Query(ctx, `SELECT a.id,a.name,a.kind,a.host_id,a.last_seen,a.last_state_at,a.last_status_json,b.generation FROM agents a LEFT JOIN waf_agent_bundles b ON b.agent_id=a.id WHERE a.deleted_at IS NULL AND a.project_id=$1 AND ($2='' OR a.host_id=NULLIF($2,'')::uuid) ORDER BY a.id`, projectID, hostID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var row dashboard.AgentEvidence
		var raw []byte
		var generation *int64
		if err := rows.Scan(&row.ID, &row.Name, &row.Kind, &row.HostID, &row.LastSeen, &row.StateAt, &raw, &generation); err != nil {
			rows.Close()
			return nil, err
		}
		row.Freshness = dashboard.HeartbeatFreshness(row.LastSeen, result.SnapshotAt)
		row.ApplyState = "unknown"
		if generation != nil {
			value := strconv.FormatInt(*generation, 10)
			row.DesiredGeneration = &value
		}
		row.Capabilities = reportedCapabilities(raw)
		result.Agents = append(result.Agents, row)
		if row.Freshness != "fresh" {
			result.Actions = append(result.Actions, dashboard.OverviewAction{ID: "heartbeat:" + row.ID, Kind: "heartbeat", Severity: "warning", TargetID: row.ID, TargetName: row.Name, ObservedAt: row.LastSeen, Message: "Heartbeat " + row.Freshness + "; current agent availability is not confirmed"})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	result.Sources["agents"] = source
	rows, err = tx.Query(ctx, `SELECT i.id,i.agent_id,i.severity,i.last_seen_at FROM host_incidents i WHERE i.project_id=$1 AND i.status IN ('open','acknowledged') AND ($2='' OR EXISTS(SELECT 1 FROM agents a WHERE a.deleted_at IS NULL AND a.id::text=i.agent_id AND a.project_id=i.project_id AND a.host_id=NULLIF($2,'')::uuid)) ORDER BY i.severity DESC,i.last_seen_at DESC`, projectID, hostID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, agent string
		var severity int
		var seen time.Time
		if err := rows.Scan(&id, &agent, &severity, &seen); err != nil {
			rows.Close()
			return nil, err
		}
		level := "warning"
		if severity >= 4 {
			level = "critical"
		} else if severity >= 3 {
			level = "high"
		}
		result.Actions = append(result.Actions, dashboard.OverviewAction{ID: id, Kind: "incident", Severity: level, TargetID: agent, ObservedAt: &seen, Message: "Unresolved runtime incident"})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	result.Sources["incidents"] = source
	if hostID != "" {
		result.Sources["certificates"] = dashboard.EvidenceSource{State: "unsupported", Message: "Credentials have no durable host association; project credential expiry is available in project scope"}
	} else {
		rows, err = tx.Query(ctx, `SELECT id,name,client_cert_pem FROM mtls_credentials WHERE project_id=$1 ORDER BY id`, projectID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id, name, certPEM string
			if err := rows.Scan(&id, &name, &certPEM); err != nil {
				rows.Close()
				return nil, err
			}
			action := certificateAction(id, name, certPEM, result.SnapshotAt)
			if action != nil {
				result.Actions = append(result.Actions, *action)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
		result.Sources["certificates"] = source
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	result.Total = len(result.Actions)
	return result, nil
}

func reportedCapabilities(raw []byte) map[string]*bool {
	result := map[string]*bool{"xdp_attached": nil, "tc_ingress": nil, "tc_egress": nil, "egress_ipv6_supported": nil, "trace_running": nil, "trace_enforcement": nil, "userspace_kill_supported": nil}
	var payload map[string]map[string]json.RawMessage
	if json.Unmarshal(raw, &payload) != nil {
		return result
	}
	for name, key := range map[string]string{"xdp_attached": "xdp_attached", "tc_ingress": "tc_ingress_attached", "tc_egress": "tc_egress_attached", "egress_ipv6_supported": "egress_ipv6_supported"} {
		var value bool
		if raw := payload["ebpf"][key]; len(raw) > 0 && string(raw) != "null" && json.Unmarshal(raw, &value) == nil {
			result[name] = &value
		}
	}
	for name, key := range map[string]string{"trace_running": "running", "trace_enforcement": "enforcement", "userspace_kill_supported": "userspace_kill_supported"} {
		var value bool
		if raw := payload["trace"][key]; len(raw) > 0 && string(raw) != "null" && json.Unmarshal(raw, &value) == nil {
			result[name] = &value
		}
	}
	return result
}
func certificateAction(id, name, certPEM string, now time.Time) *dashboard.OverviewAction {
	action := &dashboard.OverviewAction{ID: "certificate:" + id, Kind: "certificate", Severity: "warning", TargetID: id, TargetName: name, ObservedAt: &now, Message: "Certificate expiry could not be evaluated"}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return action
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return action
	}
	expires := cert.NotAfter.UTC()
	if expires.After(now.Add(30 * 24 * time.Hour)) {
		return nil
	}
	action.DueAt = &expires
	action.Message = "Certificate expires within 30 days"
	if !expires.After(now) {
		action.Severity = "critical"
		action.Message = "Certificate expired"
	}
	return action
}
