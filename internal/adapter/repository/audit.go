package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditEvent captures a single security-sensitive operation for compliance
// and forensics. Persisted in the `agent_audit` table; queried by the UI
// "Audit Log" page.
type AuditEvent struct {
	ID           string         `json:"id"`
	ProjectID    string         `json:"project_id"`
	ActorUserID  string         `json:"actor_user_id,omitempty"`
	ActorName    string         `json:"actor_name,omitempty"`
	ActorEmail   string         `json:"actor_email,omitempty"`
	Action       string         `json:"action"`
	TargetType   string         `json:"target_type"`
	TargetID     string         `json:"target_id,omitempty"`
	TargetName   string         `json:"target_name,omitempty"`
	IP           string         `json:"ip,omitempty"`
	UserAgent    string         `json:"user_agent,omitempty"`
	MetadataJSON map[string]any `json:"metadata,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
}

// Standard action names. Keep these string literals stable — they are
// queryable from the UI filter and should not drift.
const (
	AuditHostCreated       = "host.created"
	AuditHostKeyRotated    = "host.key_rotated"
	AuditHostRevoked       = "host.revoked"
	AuditHostDeleted       = "host.deleted"
	AuditHostLabelsUpdated = "host.labels_updated"
	AuditHostBulkApply     = "host.bulk_apply"
	AuditAppRouteCreated   = "app.route_created"
	AuditAppRouteUpdated   = "app.route_updated"
	AuditAppRouteDeleted   = "app.route_deleted"
	AuditAppDeleted        = "app.deleted"
	AuditAgentRejected     = "agent.rejected"

	// Application lifecycle
	AuditAppCreated = "app.created"
	AuditAppUpdated = "app.updated"

	// Maintenance mode of an application: switched on, switched off, or settings changed with the
	// state unchanged.
	AuditAppMaintenanceEnabled  = "app.maintenance_enabled"
	AuditAppMaintenanceDisabled = "app.maintenance_disabled"
	AuditAppMaintenanceUpdated  = "app.maintenance_updated"

	// TLS of an application: the settings saved, a certificate uploaded or deleted, an ACME
	// certificate requested.
	AuditAppTLSUpdated             = "app.tls_updated"
	AuditAppTLSCertificateUploaded = "app.tls_certificate_uploaded"
	AuditAppTLSCertificateDeleted  = "app.tls_certificate_deleted"
	AuditAppTLSACMERequested       = "app.tls_acme_requested"

	// WAF (project-level) config
	AuditWafConfigSaved      = "waf.config_saved"
	AuditWafAppAssigned      = "waf.app_assigned" //nolint:gosec // audit action name, not a credential
	AuditWafAppUnassigned    = "waf.app_unassigned"
	AuditWafAppConfigUpdated = "waf.app_config_updated"

	// Agent credentials
	AuditCredentialProvisioned = "credential.provisioned" //nolint:gosec // audit action name, not a credential
	AuditCredentialRevoked     = "credential.revoked"     //nolint:gosec // audit action name, not a credential

	// Project settings
	AuditProjectCreated = "project.created"
	AuditProjectUpdated = "project.updated"
	AuditProjectDeleted = "project.deleted"

	// Project membership (member changes are always audited).
	AuditMemberAdded       = "member.added"
	AuditMemberRoleChanged = "member.role_changed"
	AuditMemberRemoved     = "member.removed"

	// A user joined the project through an invite (accepted while signed in,
	// or registered with it). The actor is the joining user.
	AuditMemberJoinedByInvite = "member.joined_by_invite"

	// Correlation rules (multi-stage attack chains).
	AuditCorrelationRuleCreated = "correlation.rule_created"
	AuditCorrelationRuleUpdated = "correlation.rule_updated"
	AuditCorrelationRuleDeleted = "correlation.rule_deleted"

	// Agent lifecycle (eBPF/host agents)
	AuditAgentRegistered = "agent.registered"
	AuditAgentDeleted    = "agent.deleted"

	// Certificate keys sent to a WAF agent over its stream, and the agent's refusals
	AuditAgentCertificateDelivered = "agent.certificate_delivered"
	AuditAgentCertificateRefused   = "agent.certificate_refused"

	// Firewall (eBPF) operations
	AuditFirewallConfigUpdated     = "firewall.config_updated"
	AuditFirewallBlocklistAdded    = "firewall.blocklist_added"
	AuditFirewallBlocklistRemoved  = "firewall.blocklist_removed"
	AuditFirewallAllowlistAdded    = "firewall.allowlist_added"
	AuditFirewallAllowlistRemoved  = "firewall.allowlist_removed"
	AuditFirewallGeoUpdated        = "firewall.geo_updated"
	AuditFirewallLogCleared        = "firewall.enforcement_log_cleared"
	AuditFirewallPortPolicyAdded   = "firewall.port_policy_added"
	AuditFirewallPortPolicyRemoved = "firewall.port_policy_removed"
	AuditFirewallPortCfgUpdated    = "firewall.port_policy_config_updated"
	AuditFirewallEgressAdded       = "firewall.egress_blocklist_added"
	AuditFirewallEgressRemoved     = "firewall.egress_blocklist_removed"

	// Runtime security (trace) policies + config
	AuditTraceConfigUpdated = "trace.config_updated"
	AuditTracePolicyCreated = "trace.policy_created"
	AuditTracePolicyUpdated = "trace.policy_updated"
	AuditTracePolicyDeleted = "trace.policy_deleted"

	// Runtime security detection rules
	AuditTraceRuleCreated = "trace.rule_created"
	AuditTraceRuleUpdated = "trace.rule_updated"
	AuditTraceRuleDeleted = "trace.rule_deleted"
	AuditTraceRuleToggled = "trace.rule_toggled"

	// Incident triage
	AuditIncidentAcknowledged = "incident.acknowledged"
	AuditIncidentResolved     = "incident.resolved"

	// WAF custom rules (GUI + script mode)
	AuditCustomRuleCreated = "waf.custom_rule_created"
	AuditCustomRuleUpdated = "waf.custom_rule_updated"
	AuditCustomRuleDeleted = "waf.custom_rule_deleted"
)

type AuditRepo struct{ pool *pgxpool.Pool }

// dbtx is what an audited mutation needs from either the pool or a
// transaction, so the mutation and its audit row can share one transaction.
type dbtx interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// auditWriteFailures counts audit rows that could not be written.
// Most handlers treat the audit write as best effort, so without this a
// failing audit table went unnoticed. It is exported as a metric.
var auditWriteFailures atomic.Int64

// AuditWriteFailures returns the number of failed audit writes (project and
// system audit, including audited mutations rolled back because their audit
// row failed) since process start.
func AuditWriteFailures() int64 { return auditWriteFailures.Load() }

// noteAuditFailure logs and counts a failed audit write; nil is a no-op.
func noteAuditFailure(table, action string, err error) error {
	if err != nil {
		auditWriteFailures.Add(1)
		slog.Error("audit_write_failed", "table", table, "action", action, "err", err)
	}
	return err
}

// Log records an event. IP/UA are best-effort — callers should extract from
// request headers. Never pass raw secrets in metadata. A failure is logged
// and counted here (AuditWriteFailures), so a caller that cannot act on the
// error may ignore it without the failure going unseen.
func (r *AuditRepo) Log(ctx context.Context, ev AuditEvent) error {
	return noteAuditFailure("agent_audit", ev.Action, insertAudit(ctx, r.pool, ev))
}

// insertAudit writes one agent_audit row through q (the pool or the
// transaction of the mutation it records).
func insertAudit(ctx context.Context, q dbtx, ev AuditEvent) error {
	if ev.MetadataJSON == nil {
		ev.MetadataJSON = map[string]any{}
	}
	meta, _ := json.Marshal(ev.MetadataJSON)
	var actor any
	if ev.ActorUserID != "" {
		actor = ev.ActorUserID
	}
	var ip any
	if ev.IP != "" {
		ip = ev.IP
	}
	_, err := q.Exec(ctx, `
		INSERT INTO agent_audit
		    (project_id, actor_user_id, action, target_type, target_id, target_name, ip, user_agent, metadata)
		VALUES ($1, $2, $3, $4, NULLIF($5,''), NULLIF($6,''), $7, $8, $9::jsonb)`,
		ev.ProjectID, actor, ev.Action, ev.TargetType,
		ev.TargetID, ev.TargetName, ip, ev.UserAgent, string(meta),
	)
	return err
}

// ListByProject returns paginated audit events for a project.
// prefixes is a list of action prefixes to filter by (OR logic); empty = all.
// Returns (events, total, error).
func (r *AuditRepo) ListByProject(ctx context.Context, projectID string, prefixes []string, limit, offset int) ([]AuditEvent, int, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	// Build prefix WHERE fragment
	baseArgs := []any{projectID}
	var prefixWhere string
	filtered := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		if p != "" {
			filtered = append(filtered, p)
		}
	}
	if len(filtered) == 1 {
		// Action names contain '_' (a LIKE wildcard): match the prefix literally.
		baseArgs = append(baseArgs, escapeLike(filtered[0]))
		prefixWhere = fmt.Sprintf(" AND a.action LIKE $%d || '%%'", len(baseArgs))
	} else if len(filtered) > 1 {
		conds := make([]string, len(filtered))
		for i, p := range filtered {
			baseArgs = append(baseArgs, escapeLike(p))
			conds[i] = fmt.Sprintf("a.action LIKE $%d || '%%'", len(baseArgs))
		}
		prefixWhere = " AND (" + strings.Join(conds, " OR ") + ")"
	}

	// Count
	countSQL := "SELECT COUNT(*) FROM agent_audit a WHERE a.project_id = $1" + prefixWhere
	var total int
	if err := r.pool.QueryRow(ctx, countSQL, baseArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Data
	dataArgs := make([]any, len(baseArgs)+2)
	copy(dataArgs, baseArgs)
	dataArgs[len(baseArgs)] = limit
	dataArgs[len(baseArgs)+1] = offset
	nLimit := len(baseArgs) + 1
	nOffset := len(baseArgs) + 2

	dataSQL := fmt.Sprintf(`
		SELECT a.id, a.project_id, COALESCE(a.actor_user_id::text,''),
		       COALESCE(u.name,''), COALESCE(u.email,''),
		       a.action, a.target_type, COALESCE(a.target_id,''), COALESCE(a.target_name,''),
		       COALESCE(host(a.ip),''), COALESCE(a.user_agent,''), a.metadata, a.created_at
		  FROM agent_audit a
		  LEFT JOIN users u ON u.id = a.actor_user_id
		 WHERE a.project_id = $1%s
		 ORDER BY a.created_at DESC
		 LIMIT $%d OFFSET $%d`, prefixWhere, nLimit, nOffset)

	rows, err := r.pool.Query(ctx, dataSQL, dataArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	// An empty page is [] in JSON, never null.
	out := []AuditEvent{}
	for rows.Next() {
		var ev AuditEvent
		var meta []byte
		if err := rows.Scan(
			&ev.ID, &ev.ProjectID, &ev.ActorUserID,
			&ev.ActorName, &ev.ActorEmail,
			&ev.Action, &ev.TargetType, &ev.TargetID, &ev.TargetName,
			&ev.IP, &ev.UserAgent, &meta, &ev.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(meta, &ev.MetadataJSON)
		out = append(out, ev)
	}
	return out, total, rows.Err()
}
