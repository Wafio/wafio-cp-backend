package repository

import (
	"context"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
)

func (p *ProjectRepo) ConfigRevision(ctx context.Context, projectID string) (int64, error) {
	var revision int64
	err := p.pool.QueryRow(ctx, `SELECT waf_config_revision FROM projects WHERE id=$1`, projectID).Scan(&revision)
	return revision, err
}

// SaveConfigRevision commits desired defaults, immutable history and bundle
// generations together. Project row serialization also orders app snapshots.
func (p *ProjectRepo) SaveConfigRevision(ctx context.Context, projectID, actor string, expected int64, rules []byte, sensitivity int, rollback *int64) (int64, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var current int64
	if err := tx.QueryRow(ctx, `SELECT waf_config_revision FROM projects WHERE id=$1 FOR UPDATE`, projectID).Scan(&current); err != nil {
		return 0, err
	}
	if current != expected {
		return current, ErrConfigRevisionConflict
	}
	if _, err := tx.Exec(ctx, `INSERT INTO waf_project_config_history(project_id,revision,rules_json,sensitivity) SELECT p.id,p.waf_config_revision,c.rules_json,COALESCE(c.sensitivity,2) FROM projects p LEFT JOIN project_configs c ON c.project_id=p.id WHERE p.id=$1 ON CONFLICT(project_id,revision) DO NOTHING`, projectID); err != nil {
		return 0, err
	}
	if rollback != nil {
		if err := tx.QueryRow(ctx, `SELECT rules_json,sensitivity FROM waf_project_config_history WHERE project_id=$1 AND revision=$2`, projectID, *rollback).Scan(&rules, &sensitivity); err != nil {
			return 0, err
		}
		if rules == nil {
			rules = engine.DefaultRulesJSON()
		}
		// A revision saved by v1 keeps its legacy keys in history; the
		// restored document is rewritten to the current ones before it is checked.
		rules, _ = engine.NormalizeRulesJSON(rules)
		if err := engine.ValidateRulesJSON(rules); err != nil {
			return 0, ErrInvalidHistoricalConfig
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO project_configs(project_id,rules_json,sensitivity,updated_at) VALUES($1,$2,$3,now()) ON CONFLICT(project_id) DO UPDATE SET rules_json=EXCLUDED.rules_json,sensitivity=EXCLUDED.sensitivity,updated_at=now()`, projectID, rules, sensitivity); err != nil {
		return 0, err
	}
	current++
	if _, err := tx.Exec(ctx, `UPDATE projects SET waf_config_revision=$2 WHERE id=$1`, projectID, current); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO waf_project_config_history(project_id,revision,rules_json,sensitivity,actor_user_id) VALUES($1,$2,$3,$4,$5)`, projectID, current, rules, sensitivity, actor); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO waf_agent_bundles(agent_id,generation,updated_at) SELECT id,1,now() FROM agents WHERE deleted_at IS NULL AND project_id=$1 AND kind='waf' ON CONFLICT(agent_id) DO UPDATE SET generation=waf_agent_bundles.generation+1,updated_at=now()`, projectID); err != nil {
		return 0, err
	}
	return current, tx.Commit(ctx)
}

func (p *ProjectRepo) ListConfigHistory(ctx context.Context, projectID string, limit, offset int) ([]WAFConfigHistory, int, error) {
	if _, err := p.ConfigRevision(ctx, projectID); err != nil {
		return nil, 0, err
	}
	var total int
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM waf_project_config_history WHERE project_id=$1`, projectID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := p.pool.Query(ctx, `SELECT revision,rules_json,sensitivity,actor_user_id,created_at FROM waf_project_config_history WHERE project_id=$1 ORDER BY revision DESC LIMIT $2 OFFSET $3`, projectID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	result := []WAFConfigHistory{}
	for rows.Next() {
		var row WAFConfigHistory
		var raw []byte
		if err := rows.Scan(&row.Revision, &raw, &row.Sensitivity, &row.ActorUserID, &row.CreatedAt); err != nil {
			return nil, 0, err
		}
		row.Inherited = raw == nil
		row.RulesJSON = domain.RedactWAFConfig(raw)
		result = append(result, row)
	}
	return result, total, rows.Err()
}
