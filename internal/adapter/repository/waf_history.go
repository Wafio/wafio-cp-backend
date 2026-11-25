package repository

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
)

var ErrConfigRevisionConflict = errors.New("configuration revision changed")
var ErrInvalidHistoricalConfig = errors.New("historical configuration is incompatible with current validation")

type WAFConfigHistory struct {
	ProjectRevision    *int64          `json:"project_revision"`
	ProjectRulesJSON   json.RawMessage `json:"project_rules_json"`
	ProjectSensitivity *int            `json:"project_sensitivity"`
	Revision           int64           `json:"revision"`
	RulesJSON          json.RawMessage `json:"rules_json"`
	Sensitivity        int             `json:"sensitivity"`
	ActorUserID        *string         `json:"actor_user_id"`
	CreatedAt          time.Time       `json:"created_at"`
	Inherited          bool            `json:"inherited"`
}

func (r *WAFRepo) AppConfigRevision(ctx context.Context, projectID, appID string) (int64, error) {
	var revision int64
	err := r.pool.QueryRow(ctx, `SELECT waf_config_revision FROM apps WHERE project_id=$1 AND id=$2`, projectID, appID).Scan(&revision)
	return revision, err
}

// SaveAppConfigRevision serializes edits/reset/rollback on the app row. Snapshot,
// effective override and bundle generation commit together. Raw snapshots are
// never returned directly by the history read API.
func (r *WAFRepo) SaveAppConfigRevision(ctx context.Context, projectID, appID, actor string, expected int64, rules []byte, sensitivity int, rollback *int64) (int64, error) {
	leave, err := enterNestedTx(ctx) // it waits for the row of the application, with a connection in hand
	if err != nil {
		return 0, err
	}
	defer leave()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// Lock project before app to serialize captured project provenance against
	// project-default edits. The captured input is desired configuration, not ACK.
	var projectRevision int64
	if err := tx.QueryRow(ctx, `SELECT waf_config_revision FROM projects WHERE id=$1 FOR SHARE`, projectID).Scan(&projectRevision); err != nil {
		return 0, err
	}
	var current int64
	if err := tx.QueryRow(ctx, `SELECT waf_config_revision FROM apps WHERE id=$1 AND project_id=$2 FOR UPDATE`, appID, projectID).Scan(&current); err != nil {
		return 0, err
	}
	if current != expected {
		return current, ErrConfigRevisionConflict
	}
	if _, err := tx.Exec(ctx, `INSERT INTO waf_app_config_history(app_id,project_id,revision,rules_json,sensitivity) SELECT a.id,a.project_id,a.waf_config_revision,c.rules_json,COALESCE(c.sensitivity,2) FROM apps a LEFT JOIN app_configs c ON c.app_id=a.id WHERE a.id=$1 AND a.project_id=$2 ON CONFLICT(app_id,revision) DO NOTHING`, appID, projectID); err != nil {
		return 0, err
	}
	if rollback != nil {
		if err := tx.QueryRow(ctx, `SELECT rules_json,sensitivity FROM waf_app_config_history WHERE project_id=$1 AND app_id=$2 AND revision=$3`, projectID, appID, *rollback).Scan(&rules, &sensitivity); err != nil {
			return 0, err
		}
	}
	if rollback != nil && rules != nil {
		// A revision saved by v1 keeps its legacy keys in history; the
		// restored document is rewritten to the current ones before it is checked.
		rules, _ = engine.NormalizeRulesJSON(rules)
		if err := engine.ValidateRulesJSON(rules); err != nil {
			return 0, ErrInvalidHistoricalConfig
		}
	}
	if rules == nil {
		if _, err := tx.Exec(ctx, `DELETE FROM app_configs WHERE app_id=$1`, appID); err != nil {
			return 0, err
		}
	} else {
		if _, err := tx.Exec(ctx, `INSERT INTO app_configs(app_id,rules_json,sensitivity,generation,updated_at) VALUES($1,$2,$3,1,now()) ON CONFLICT(app_id) DO UPDATE SET rules_json=EXCLUDED.rules_json,sensitivity=EXCLUDED.sensitivity,generation=app_configs.generation+1,updated_at=now()`, appID, rules, sensitivity); err != nil {
			return 0, err
		}
	}
	current++
	if _, err := tx.Exec(ctx, `UPDATE apps SET waf_config_revision=$3 WHERE id=$1 AND project_id=$2`, appID, projectID, current); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO waf_app_config_history(app_id,project_id,revision,rules_json,sensitivity,actor_user_id,project_revision,project_rules_json,project_sensitivity) SELECT $1,p.id,$3,$4,$5,$6,p.waf_config_revision,c.rules_json,c.sensitivity FROM projects p LEFT JOIN project_configs c ON c.project_id=p.id WHERE p.id=$2`, appID, projectID, current, rules, sensitivity, actor); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO waf_agent_bundles(agent_id,generation,updated_at) SELECT agent_id,1,now() FROM waf_agent_apps WHERE app_id=$1 AND enabled=TRUE ON CONFLICT(agent_id) DO UPDATE SET generation=waf_agent_bundles.generation+1,updated_at=now()`, appID); err != nil {
		return 0, err
	}
	return current, tx.Commit(ctx)
}

func (r *WAFRepo) ListAppConfigHistory(ctx context.Context, projectID, appID string, limit, offset int) ([]WAFConfigHistory, int, error) {
	if _, err := r.AppConfigRevision(ctx, projectID, appID); err != nil {
		return nil, 0, err
	}
	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM waf_app_config_history WHERE project_id=$1 AND app_id=$2`, projectID, appID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.pool.Query(ctx, `SELECT revision,rules_json,sensitivity,actor_user_id,created_at,project_revision,project_rules_json,project_sensitivity FROM waf_app_config_history WHERE project_id=$1 AND app_id=$2 ORDER BY revision DESC LIMIT $3 OFFSET $4`, projectID, appID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	result := []WAFConfigHistory{}
	for rows.Next() {
		var row WAFConfigHistory
		var raw, projectRaw []byte
		if err := rows.Scan(&row.Revision, &raw, &row.Sensitivity, &row.ActorUserID, &row.CreatedAt, &row.ProjectRevision, &projectRaw, &row.ProjectSensitivity); err != nil {
			return nil, 0, err
		}
		row.ProjectRulesJSON = domain.RedactWAFConfig(projectRaw)
		row.Inherited = raw == nil
		row.RulesJSON = domain.RedactWAFConfig(raw)
		result = append(result, row)
	}
	return result, total, rows.Err()
}
