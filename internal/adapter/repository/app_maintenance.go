package repository

import (
	"context"
	"encoding/json"

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
	return decodeMaintenance(raw)
}

func decodeMaintenance(raw []byte) (domain.Maintenance, error) {
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

// UpdateMaintenance reads the maintenance object of an application, lets apply turn it into the
// new one, stores that and bumps the bundle generation of the agent that serves the application,
// all in one transaction that holds the application row. Two saves at once therefore run one after
// the other: the second sees what the first stored. The bundle of the serving agent is locked as
// well (lockAgentBundle), so saves of two applications on one agent are measured one after the
// other. apply gets the stored value; its error is
// returned as it is and nothing is written. The new value must be normalized. It returns the
// value that was replaced and the value that was stored, and pgx.ErrNoRows when the application
// is not in the project.
//
// apply may query the pool while the transaction holds a connection; enterNestedTx keeps the
// saves that wait for the row from using up the pool.
func (r *AppRepo) UpdateMaintenance(ctx context.Context, projectID, appID string,
	apply func(stored domain.Maintenance) (domain.Maintenance, error)) (stored, saved domain.Maintenance, err error) {
	leave, err := enterNestedTx(ctx)
	if err != nil {
		return stored, saved, err
	}
	defer leave()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return stored, saved, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var raw []byte
	var agentID string
	if err = tx.QueryRow(ctx, `SELECT a.maintenance,
		COALESCE((SELECT waa.agent_id::text FROM waf_agent_apps waa WHERE waa.app_id = a.id AND waa.enabled = TRUE LIMIT 1), '')
		FROM apps a WHERE a.id = $1 AND a.project_id = $2 FOR UPDATE`, appID, projectID).Scan(&raw, &agentID); err != nil {
		return stored, saved, err
	}
	if agentID != "" {
		if err = lockAgentBundle(ctx, tx, agentID); err != nil {
			return stored, saved, err
		}
	}
	if stored, err = decodeMaintenance(raw); err != nil {
		return stored, saved, err
	}
	if saved, err = apply(stored); err != nil {
		return stored, saved, err
	}
	if raw, err = json.Marshal(saved); err != nil {
		return stored, saved, err
	}
	if _, err = tx.Exec(ctx, `UPDATE apps SET maintenance = $3::jsonb, updated_at = NOW() WHERE id = $1 AND project_id = $2`,
		appID, projectID, string(raw)); err != nil {
		return stored, saved, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO waf_agent_bundles (agent_id,generation,updated_at)
 SELECT agent_id,1,NOW() FROM waf_agent_apps WHERE app_id=$1 AND enabled=TRUE
 ON CONFLICT(agent_id) DO UPDATE SET generation=waf_agent_bundles.generation+1,updated_at=NOW()`, appID); err != nil {
		return stored, saved, err
	}
	return stored, saved, tx.Commit(ctx)
}
