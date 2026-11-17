package repository

import (
	"context"
	"encoding/json"
	"time"
)

type SystemAuditEvent struct {
	ID          string `json:"id"`
	ActorUserID string `json:"actor_user_id"`
	ActorEmail  string `json:"actor_email"`
	Action      string `json:"action"`
	TargetType  string `json:"target_type"`
	TargetID    string `json:"target_id"`
	Outcome     string `json:"outcome"`
	HTTPStatus  int    `json:"http_status"`
	IP          string `json:"ip"`
	UserAgent   string `json:"user_agent"`
	// Metadata holds details of the event (migration 000110), e.g. the
	// settings changed and their new values; never a secret. nil/empty is
	// stored as NULL.
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

// LogSystem records a system-scope event. A failure is logged and counted
// (AuditWriteFailures) before it is returned.
func (r *AuditRepo) LogSystem(ctx context.Context, event SystemAuditEvent) error {
	return noteAuditFailure("system_audit", event.Action, insertSystemAudit(ctx, r.pool, event))
}

// system_audit column bounds (migration 000073): target_id varchar(64),
// user_agent varchar(512).
const (
	maxSystemAuditTargetID  = 64
	maxSystemAuditUserAgent = 512
)

func insertSystemAudit(ctx context.Context, q dbtx, event SystemAuditEvent) error {
	// The user agent is client-chosen and the target is often an email
	// (up to 255 characters): cut both to their column and make them
	// storable, so an audit row written in the same transaction as the
	// change it records can never fail that change.
	targetID := capStoredText(sanitizeStoredText(event.TargetID), maxSystemAuditTargetID)
	userAgent := capStoredText(sanitizeStoredText(event.UserAgent), maxSystemAuditUserAgent)
	var meta any // NULL without details
	if len(event.Metadata) > 0 {
		b, err := json.Marshal(event.Metadata)
		if err != nil {
			return err
		}
		meta = string(b)
	}
	_, err := q.Exec(ctx, `INSERT INTO system_audit(actor_user_id,action,target_type,target_id,outcome,http_status,ip,user_agent,metadata) VALUES(NULLIF($1,'')::uuid,$2,$3,NULLIF($4,''),$5,$6,NULLIF($7,'')::inet,$8,$9::jsonb)`, event.ActorUserID, event.Action, event.TargetType, targetID, event.Outcome, event.HTTPStatus, event.IP, userAgent, meta)
	return err
}

func (r *AuditRepo) ListSystem(ctx context.Context, limit, offset int) ([]SystemAuditEvent, int, error) {
	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM system_audit`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.pool.Query(ctx, `SELECT a.id,COALESCE(a.actor_user_id::text,''),COALESCE(u.email,''),a.action,a.target_type,COALESCE(a.target_id,''),a.outcome,a.http_status,COALESCE(host(a.ip),''),COALESCE(a.user_agent,''),a.metadata,a.created_at FROM system_audit a LEFT JOIN users u ON u.id = a.actor_user_id ORDER BY a.created_at DESC,a.id LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	events := []SystemAuditEvent{}
	for rows.Next() {
		var event SystemAuditEvent
		var meta []byte
		if err := rows.Scan(&event.ID, &event.ActorUserID, &event.ActorEmail, &event.Action, &event.TargetType, &event.TargetID, &event.Outcome, &event.HTTPStatus, &event.IP, &event.UserAgent, &meta, &event.CreatedAt); err != nil {
			return nil, 0, err
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &event.Metadata) // written by insertSystemAudit: always an object
		}
		events = append(events, event)
	}
	return events, total, rows.Err()
}
