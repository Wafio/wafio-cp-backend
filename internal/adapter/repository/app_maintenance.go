package repository

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// GetMaintenance returns the stored maintenance object of an application of the project. An
// application that was never configured reads as the zero value with empty lists. It returns
// pgx.ErrNoRows when the application is not in the project.
func (r *AppRepo) GetMaintenance(ctx context.Context, projectID, appID string) (domain.Maintenance, error) {
	var raw []byte
	if err := r.pool.QueryRow(ctx, `SELECT maintenance FROM apps WHERE id = $1 AND project_id = $2`, appID, projectID).Scan(&raw); err != nil {
		return domain.Maintenance{}, err
	}
	var m domain.Maintenance
	if err := json.Unmarshal(raw, &m); err != nil {
		return domain.Maintenance{}, err
	}
	if m.AllowIPs == nil {
		m.AllowIPs = []string{}
	}
	if m.AllowPaths == nil {
		m.AllowPaths = []string{}
	}
	return m, nil
}

// SetMaintenance replaces the maintenance object of an application and bumps the bundle generation
// of the agent that serves it, in one transaction. m must be normalized. It returns pgx.ErrNoRows
// when the application is not in the project.
func (r *AppRepo) SetMaintenance(ctx context.Context, projectID, appID string, m domain.Maintenance) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	result, err := tx.Exec(ctx, `UPDATE apps SET maintenance = $3::jsonb, updated_at = NOW() WHERE id = $1 AND project_id = $2`,
		appID, projectID, string(raw))
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	_, err = tx.Exec(ctx, `INSERT INTO waf_agent_bundles (agent_id,generation,updated_at)
 SELECT agent_id,1,NOW() FROM waf_agent_apps WHERE app_id=$1 AND enabled=TRUE
 ON CONFLICT(agent_id) DO UPDATE SET generation=waf_agent_bundles.generation+1,updated_at=NOW()`, appID)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
