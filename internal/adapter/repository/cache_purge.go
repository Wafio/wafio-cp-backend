package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The limits of the removal queue of one application.
const (
	// CachePurgeMaxPending is how many removals may wait for one application.
	CachePurgeMaxPending = 20
	// CachePurgeKept is how many of the newest removals are kept for one application; one that still
	// waits is never deleted.
	CachePurgeKept = 20
	// CachePurgeExpiry is how long a removal waits for an agent that does not come back. A removal
	// older than that is failed with the code expired, so a gone agent cannot fill the queue for good.
	CachePurgeExpiry = 7 * 24 * time.Hour
)

var (
	// ErrCacheOff: the saved cache of the application is off, so nothing is stored to remove.
	ErrCacheOff = errors.New("the cache of the application is off")
	// ErrPurgeQueueFull: CachePurgeMaxPending removals are waiting for the application.
	ErrPurgeQueueFull = errors.New("too many removals are waiting")
)

// CachePurge is a request to remove stored copies of one application from the cache of its agent.
type CachePurge struct {
	ID, AppID, ProjectID string
	// Scope is url, prefix or app; URL is empty for app.
	Scope, URL string
	// State is pending, done or failed; Error is the fixed code of a failure.
	State, Error string
	// By is the name of the user who asked, "" when that user is gone.
	By string
	// AgentID and AgentName are the agent that answered, "" while pending.
	AgentID, AgentName string
	CreatedAt          time.Time
	FinishedAt         *time.Time
}

// CreateCachePurge queues a removal for the application, which the caller has normalized. It returns
// ErrCacheOff when the saved cache is off and ErrPurgeQueueFull when the application already has
// CachePurgeMaxPending removals waiting, and pgx.ErrNoRows when the application is not in the
// project. Waiting removals older than CachePurgeExpiry fail first, and rows past the newest
// CachePurgeKept are deleted unless they wait.
func (r *EdgeRepo) CreateCachePurge(ctx context.Context, projectID, appID, userID, scope, url string) (CachePurge, error) {
	if !canonicalIDs(&projectID, &appID) {
		return CachePurge{}, pgx.ErrNoRows
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return CachePurge{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var on bool
	if err := tx.QueryRow(ctx, `SELECT COALESCE((cache->>'enabled')::boolean, FALSE) FROM apps WHERE id = $1 AND project_id = $2 FOR UPDATE`,
		appID, projectID).Scan(&on); err != nil {
		return CachePurge{}, err
	}
	if !on {
		return CachePurge{}, ErrCacheOff
	}
	if _, err := tx.Exec(ctx, `UPDATE app_cache_purges SET state = 'failed', error = 'expired', finished_at = NOW()
		WHERE app_id = $1 AND state = 'pending' AND created_at < NOW() - make_interval(secs => $2)`, appID, CachePurgeExpiry.Seconds()); err != nil {
		return CachePurge{}, err
	}
	var pending int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM app_cache_purges WHERE app_id = $1 AND state = 'pending'`, appID).Scan(&pending); err != nil {
		return CachePurge{}, err
	}
	if pending >= CachePurgeMaxPending {
		return CachePurge{}, ErrPurgeQueueFull
	}
	var by any
	if u, err := uuid.Parse(userID); err == nil {
		by = u.String()
	}
	p := CachePurge{ID: uuid.NewString(), AppID: appID, ProjectID: projectID, Scope: scope, URL: url, State: "pending"}
	if err := tx.QueryRow(ctx, `INSERT INTO app_cache_purges (id, app_id, project_id, scope, url, created_by) VALUES ($1, $2, $3, $4, $5, $6::uuid)
		RETURNING created_at, COALESCE((SELECT COALESCE(NULLIF(u.name, ''), u.email) FROM users u WHERE u.id = $6::uuid), '')`,
		p.ID, appID, projectID, scope, url, by).Scan(&p.CreatedAt, &p.By); err != nil {
		return CachePurge{}, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM app_cache_purges WHERE app_id = $1 AND state <> 'pending' AND id NOT IN
		(SELECT id FROM app_cache_purges WHERE app_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2)`, appID, CachePurgeKept); err != nil {
		return CachePurge{}, err
	}
	return p, tx.Commit(ctx)
}

const purgeColumns = `SELECT p.id::text, p.app_id::text, p.project_id::text, p.scope, p.url, p.state, p.error,
	COALESCE(NULLIF(u.name, ''), u.email, ''), COALESCE(p.agent_id::text, ''), COALESCE(ag.name, ''), p.created_at, p.finished_at
	FROM app_cache_purges p
	LEFT JOIN users u ON u.id = p.created_by
	LEFT JOIN agents ag ON ag.id = p.agent_id AND ag.deleted_at IS NULL`

func scanPurges(rows pgx.Rows) ([]CachePurge, error) {
	defer rows.Close()
	out := []CachePurge{}
	for rows.Next() {
		var p CachePurge
		if err := rows.Scan(&p.ID, &p.AppID, &p.ProjectID, &p.Scope, &p.URL, &p.State, &p.Error, &p.By, &p.AgentID, &p.AgentName,
			&p.CreatedAt, &p.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListCachePurges returns the newest removals of the application, newest first.
func (r *EdgeRepo) ListCachePurges(ctx context.Context, projectID, appID string, limit int) ([]CachePurge, error) {
	if !canonicalIDs(&projectID, &appID) {
		return []CachePurge{}, nil
	}
	rows, err := r.pool.Query(ctx, purgeColumns+` WHERE p.app_id = $1 AND p.project_id = $2 ORDER BY p.created_at DESC, p.id DESC LIMIT $3`,
		appID, projectID, limit)
	if err != nil {
		return nil, err
	}
	return scanPurges(rows)
}

// PendingCachePurges returns the removals that wait for the agent: pending, not expired, for an
// application of the project that has an enabled assignment to it. With appID set, only that
// application's, oldest first.
func (r *EdgeRepo) PendingCachePurges(ctx context.Context, projectID, agentID, appID string) ([]CachePurge, error) {
	if !canonicalIDs(&projectID, &agentID) {
		return nil, nil
	}
	var app any
	if appID != "" {
		if !canonicalIDs(&appID) {
			return nil, nil
		}
		app = appID
	}
	rows, err := r.pool.Query(ctx, purgeColumns+`
		JOIN waf_agent_apps waa ON waa.app_id = p.app_id AND waa.enabled = TRUE AND waa.agent_id = $2
		JOIN agents cur ON cur.id = waa.agent_id AND cur.project_id = p.project_id AND cur.kind = 'waf' AND cur.deleted_at IS NULL
		WHERE p.project_id = $1 AND p.state = 'pending' AND p.created_at >= NOW() - make_interval(secs => $4)
		  AND ($3::uuid IS NULL OR p.app_id = $3::uuid)
		ORDER BY p.created_at, p.id LIMIT 100`, projectID, agentID, app, CachePurgeExpiry.Seconds())
	if err != nil {
		return nil, err
	}
	return scanPurges(rows)
}

// FinishCachePurge records the answer of the agent: state done, or failed with the fixed code. It
// changes nothing, and reports false, unless the removal is pending and the agent has the
// application assigned in this project.
func (r *EdgeRepo) FinishCachePurge(ctx context.Context, projectID, agentID, id, state, code string) (bool, error) {
	if !canonicalIDs(&projectID, &agentID, &id) {
		return false, nil
	}
	tag, err := r.pool.Exec(ctx, `UPDATE app_cache_purges p SET state = $4, error = $5, agent_id = $3, finished_at = NOW()
		FROM waf_agent_apps waa
		WHERE p.id = $2 AND p.project_id = $1 AND p.state = 'pending'
		  AND waa.app_id = p.app_id AND waa.agent_id = $3 AND waa.enabled = TRUE`, projectID, id, agentID, state, code)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
