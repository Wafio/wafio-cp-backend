package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

type IncidentRepo struct {
	pool *pgxpool.Pool
}

// Upsert atomically inserts or increments the active grouping key, including concurrent first sightings.
func (r *IncidentRepo) Upsert(ctx context.Context, in domain.HostIncident, count int64) error {
	_, err := r.pool.Exec(ctx, `
 INSERT INTO host_incidents(project_id,agent_id,technique_id,comm,tactic,severity,severity_name,event_count,sample_description)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
 ON CONFLICT(project_id,agent_id,technique_id,comm) WHERE status <> 'resolved'
 DO UPDATE SET event_count=host_incidents.event_count+EXCLUDED.event_count,
 last_seen_at=now(),updated_at=now(),severity=GREATEST(host_incidents.severity,EXCLUDED.severity),
 severity_name=CASE WHEN EXCLUDED.severity>host_incidents.severity THEN EXCLUDED.severity_name ELSE host_incidents.severity_name END`,
		in.ProjectID, in.AgentID, in.TechniqueID, in.Comm, in.Tactic, in.Severity, in.SeverityName, count, in.SampleDesc)
	return err
}

// ResolveStale auto-resolves OPEN (not acknowledged) incidents whose last_seen
// is older than the cutoff. Returns the number resolved.
func (r *IncidentRepo) ResolveStale(ctx context.Context, projectID string, olderThan time.Duration) (int64, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE host_incidents
		   SET status='resolved', resolved_at=now(), resolved_by='auto', updated_at=now()
		 WHERE project_id=$1 AND status='open' AND last_seen_at < now() - $2::interval`,
		projectID, olderThan.String())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// List returns incidents for a project, optionally filtered by status (empty =
// all), open-first then severity desc then most-recent, plus the total count.
func (r *IncidentRepo) List(ctx context.Context, projectID, status string, limit, offset int, hostIDs ...string) ([]domain.HostIncident, int, error) {
	hostID := ""
	if len(hostIDs) > 0 {
		hostID = hostIDs[0]
	}
	var total int
	if err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM host_incidents WHERE project_id=$1 AND ($2='' OR status=$2 OR ($2='unresolved' AND status IN ('open','acknowledged'))) AND ($3='' OR EXISTS (SELECT 1 FROM agents a WHERE a.deleted_at IS NULL AND a.id::text=host_incidents.agent_id AND a.project_id=host_incidents.project_id AND a.host_id=NULLIF($3,'')::uuid))`,
		projectID, status, hostID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, project_id, agent_id, technique_id, tactic, comm, severity, severity_name,
		       status, event_count, first_seen_at, last_seen_at, acknowledged_at, acknowledged_by,
		       resolved_at, resolved_by, sample_description, created_at, updated_at
		  FROM host_incidents
		 WHERE project_id=$1 AND ($2='' OR status=$2 OR ($2='unresolved' AND status IN ('open','acknowledged'))) AND ($3='' OR EXISTS (SELECT 1 FROM agents a WHERE a.deleted_at IS NULL AND a.id::text=host_incidents.agent_id AND a.project_id=host_incidents.project_id AND a.host_id=NULLIF($3,'')::uuid))
		 ORDER BY (status='open') DESC, severity DESC, last_seen_at DESC
		 LIMIT $4 OFFSET $5`, projectID, status, hostID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []domain.HostIncident{}
	for rows.Next() {
		var i domain.HostIncident
		if err := rows.Scan(&i.ID, &i.ProjectID, &i.AgentID, &i.TechniqueID, &i.Tactic, &i.Comm,
			&i.Severity, &i.SeverityName, &i.Status, &i.EventCount, &i.FirstSeenAt, &i.LastSeenAt,
			&i.AcknowledgedAt, &i.AcknowledgedBy, &i.ResolvedAt, &i.ResolvedBy, &i.SampleDesc,
			&i.CreatedAt, &i.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, i)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// Stats computes the overview triage summary over incidents whose first_seen is
// within the window. MTTA/MTTR are over acked/resolved (non-auto) samples.
func (r *IncidentRepo) Stats(ctx context.Context, projectID string, since time.Time) (domain.IncidentStats, error) {
	s := domain.IncidentStats{OpenBySeverity: map[string]int{"critical": 0, "high": 0}}
	// Active-state counts (open/acknowledged) reflect CURRENT state and are not
	// time-windowed — an open incident is open regardless of when it started.
	// Only MTTA/MTTR below use the window. This keeps the "Open Incidents"
	// headline consistent with the (un-windowed) active-incident list.
	rows, err := r.pool.Query(ctx, `
		SELECT status, severity_name, count(*)
		  FROM host_incidents
		 WHERE project_id=$1 AND status <> 'resolved'
		 GROUP BY status, severity_name`, projectID)
	if err != nil {
		return s, err
	}
	for rows.Next() {
		var status, sevName string
		var n int
		if err := rows.Scan(&status, &sevName, &n); err != nil {
			rows.Close()
			return s, err
		}
		switch status {
		case "open":
			s.Open += n
			s.Unacknowledged += n
			if _, ok := s.OpenBySeverity[sevName]; ok {
				s.OpenBySeverity[sevName] += n
			}
		case "acknowledged":
			s.Acknowledged += n
			if _, ok := s.OpenBySeverity[sevName]; ok {
				s.OpenBySeverity[sevName] += n
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return s, err
	}

	var mtta, mttr *float64
	if err := r.pool.QueryRow(ctx, `
		SELECT EXTRACT(EPOCH FROM avg(acknowledged_at - first_seen_at))
		  FROM host_incidents
		 WHERE project_id=$1 AND first_seen_at >= $2 AND acknowledged_at IS NOT NULL`,
		projectID, since).Scan(&mtta); err != nil {
		return s, err
	}
	if err := r.pool.QueryRow(ctx, `
		SELECT EXTRACT(EPOCH FROM avg(resolved_at - first_seen_at))
		  FROM host_incidents
		 WHERE project_id=$1 AND first_seen_at >= $2 AND resolved_at IS NOT NULL AND resolved_by <> 'auto'`,
		projectID, since).Scan(&mttr); err != nil {
		return s, err
	}
	if mtta != nil {
		v := int64(*mtta)
		s.MTTASeconds = &v
	}
	if mttr != nil {
		v := int64(*mttr)
		s.MTTRSeconds = &v
	}
	return s, nil
}

// Acknowledge sets an OPEN incident to acknowledged. Returns whether a row changed.
func (r *IncidentRepo) Acknowledge(ctx context.Context, projectID, id, userID string) (bool, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE host_incidents
		   SET status='acknowledged', acknowledged_at=now(), acknowledged_by=$3, updated_at=now()
		 WHERE project_id=$1 AND id=$2 AND status='open'`, projectID, id, userID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// Resolve sets an incident (open or acknowledged) to resolved.
func (r *IncidentRepo) Resolve(ctx context.Context, projectID, id, userID string) (bool, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE host_incidents
		   SET status='resolved', resolved_at=now(), resolved_by=$3, updated_at=now()
		 WHERE project_id=$1 AND id=$2 AND status <> 'resolved'`, projectID, id, userID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// Exists reports whether an incident id belongs to the project.
func (r *IncidentRepo) Exists(ctx context.Context, projectID, id string) (bool, error) {
	var n int
	err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM host_incidents WHERE project_id=$1 AND id=$2`, projectID, id).Scan(&n)
	return n > 0, err
}
