package repository

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// ReplaceAssignment preserves app identity/config/history and replaces its
// active route binding. Disabled historical bindings remain for evidence.
//
// The application row is locked, so a move and a maintenance save (UpdateMaintenance) run one
// after the other. When agentID is set and is not the agent that serves the application now,
// admit is called with the stored maintenance object, before anything is written; an error from
// it is returned as it is and the move does not happen. A nil admit checks nothing.
func (r *WAFRepo) ReplaceAssignment(ctx context.Context, projectID, appID, agentID, mode string, admit func(stored domain.Maintenance) error) error {
	if admit != nil {
		leave, err := enterNestedTx(ctx)
		if err != nil {
			return err
		}
		defer leave()
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var id string
	var rawMaintenance []byte
	if err := tx.QueryRow(ctx, `SELECT id, maintenance FROM apps WHERE id=$1 AND project_id=$2 FOR UPDATE`, appID, projectID).Scan(&id, &rawMaintenance); err != nil {
		return err
	}
	if agentID != "" {
		if err := tx.QueryRow(ctx, `SELECT id FROM agents WHERE deleted_at IS NULL AND id=$1 AND project_id=$2 AND kind='waf'`, agentID, projectID).Scan(&id); err != nil {
			return err
		}
		if admit != nil {
			var current string
			err := tx.QueryRow(ctx, `SELECT agent_id FROM waf_agent_apps WHERE app_id=$1 AND enabled=TRUE`, appID).Scan(&current)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if current != agentID {
				stored, err := decodeMaintenance(rawMaintenance)
				if err != nil {
					return err
				}
				if err := admit(stored); err != nil {
					return err
				}
			}
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE waf_agent_apps SET enabled=FALSE,updated_at=now() WHERE app_id=$1`, appID); err != nil {
		return err
	}
	if agentID != "" {
		if _, err = tx.Exec(ctx, `INSERT INTO waf_agent_apps(agent_id,app_id,mode,enabled,updated_at) VALUES($1,$2,$3,TRUE,now()) ON CONFLICT(agent_id,app_id) DO UPDATE SET mode=EXCLUDED.mode,enabled=TRUE,updated_at=now()`, agentID, appID, mode); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO waf_agent_bundles(agent_id,generation,updated_at) SELECT agent_id,1,now() FROM waf_agent_apps WHERE app_id=$1 ON CONFLICT(agent_id) DO UPDATE SET generation=waf_agent_bundles.generation+1,updated_at=now()`, appID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *WAFRepo) ResetAppConfig(ctx context.Context, projectID, appID string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var id string
	if err := tx.QueryRow(ctx, `SELECT id FROM apps WHERE id=$1 AND project_id=$2 FOR UPDATE`, appID, projectID).Scan(&id); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM app_configs WHERE app_id=$1`, appID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO waf_agent_bundles(agent_id,generation,updated_at) SELECT agent_id,1,now() FROM waf_agent_apps WHERE app_id=$1 AND enabled=TRUE ON CONFLICT(agent_id) DO UPDATE SET generation=waf_agent_bundles.generation+1,updated_at=now()`, appID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// GetAssignment includes the existing mode so moving a monitored app preserves intent.
func (r *WAFRepo) GetAssignment(ctx context.Context, projectID, appID string) (agentID, mode string, err error) {
	err = r.pool.QueryRow(ctx, `SELECT waa.agent_id, waa.mode FROM waf_agent_apps waa JOIN apps ap ON ap.id=waa.app_id JOIN agents a ON a.id=waa.agent_id AND a.project_id=ap.project_id AND a.deleted_at IS NULL WHERE waa.app_id=$1 AND ap.project_id=$2 AND waa.enabled=true LIMIT 1`, appID, projectID).Scan(&agentID, &mode)
	return
}
