package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

type WafCustomRulesRepo struct {
	pool *pgxpool.Pool
}

func (r *WafCustomRulesRepo) List(ctx context.Context, appID string) ([]domain.CustomRule, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, app_id, name, description, enabled, priority, mode,
		       conditions, condition_logic, action, script, tuning, created_at, updated_at
		FROM waf_custom_rules
		WHERE app_id = $1
		ORDER BY priority ASC, created_at ASC
	`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := []domain.CustomRule{}
	for rows.Next() {
		var rule domain.CustomRule
		var condJSON, tuningJSON []byte
		if err := rows.Scan(
			&rule.ID, &rule.AppID, &rule.Name, &rule.Description, &rule.Enabled,
			&rule.Priority, &rule.Mode, &condJSON, &rule.ConditionLogic,
			&rule.Action, &rule.Script, &tuningJSON, &rule.CreatedAt, &rule.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if len(condJSON) > 0 {
			_ = json.Unmarshal(condJSON, &rule.Conditions)
		}
		if len(tuningJSON) > 0 {
			_ = json.Unmarshal(tuningJSON, &rule.Tuning)
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func (r *WafCustomRulesRepo) ListGUIRulesRaw(ctx context.Context, appID string) ([]json.RawMessage, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT json_build_object(
			'id', id, 'name', name, 'enabled', enabled, 'priority', priority,
			'created_at', EXTRACT(EPOCH FROM created_at)::bigint,
			'logic', condition_logic, 'conditions', conditions, 'action', action
		)
		FROM waf_custom_rules
		WHERE app_id = $1 AND mode = 'gui' AND enabled = true
		ORDER BY priority ASC, created_at ASC
	`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []json.RawMessage{}
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}

func (r *WafCustomRulesRepo) ListScriptRulesRaw(ctx context.Context, appID string) ([]json.RawMessage, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT json_build_object(
			'id', id, 'name', name, 'enabled', enabled, 'priority', priority,
			'created_at', EXTRACT(EPOCH FROM created_at)::bigint,
			'script', script
		)
		FROM waf_custom_rules
		WHERE app_id = $1 AND mode = 'script' AND enabled = true
		ORDER BY priority ASC, created_at ASC
	`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []json.RawMessage{}
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}

// ListTuningRulesRaw returns the app's enabled mode='tuning' rules as
// engine.TuningRule-shaped JSON, ordered by priority then creation time so the
// agent's stable sort sees a deterministic sequence. The keys mirror
// engine.TuningRule's json tags exactly; missing tuning sub-objects fall back
// to engine defaults (scope=and/[], target=request/exact, engine=both,
// effect={}).
func (r *WafCustomRulesRepo) ListTuningRulesRaw(ctx context.Context, appID string) ([]json.RawMessage, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT jsonb_build_object(
			'id', id, 'name', name, 'enabled', enabled, 'priority', priority,
			'created_at', EXTRACT(EPOCH FROM created_at)::bigint,
			'scope', COALESCE(tuning->'scope', '{"logic":"and","conditions":[]}'::jsonb),
			'target', COALESCE(tuning->'target', '{"components":["request"],"match":"exact"}'::jsonb),
			'engine', COALESCE(tuning->>'engine', 'both'),
			'effect', COALESCE(tuning->'effect', '{}'::jsonb)
		)
		FROM waf_custom_rules
		WHERE app_id = $1 AND mode = 'tuning' AND enabled = true
		ORDER BY priority ASC, created_at ASC
	`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []json.RawMessage{}
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}

// CountByApp returns the number of custom rules (any mode) stored for an app,
// for the per-app rule cap enforced at create time.
func (r *WafCustomRulesRepo) CountByApp(ctx context.Context, appID string) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM waf_custom_rules WHERE app_id = $1`, appID).Scan(&n)
	return n, err
}

// GetByID returns one custom rule scoped to appID, or (nil, nil) when the rule
// does not exist under that app. Callers must have already established that
// the app belongs to the caller's project.
func (r *WafCustomRulesRepo) GetByID(ctx context.Context, appID, ruleID string) (*domain.CustomRule, error) {
	var rule domain.CustomRule
	var condJSON, tuningJSON []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id, app_id, name, description, enabled, priority, mode,
		       conditions, condition_logic, action, script, tuning, created_at, updated_at
		FROM waf_custom_rules
		WHERE id = $1 AND app_id = $2
	`, ruleID, appID).Scan(
		&rule.ID, &rule.AppID, &rule.Name, &rule.Description, &rule.Enabled,
		&rule.Priority, &rule.Mode, &condJSON, &rule.ConditionLogic,
		&rule.Action, &rule.Script, &tuningJSON, &rule.CreatedAt, &rule.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(condJSON) > 0 {
		_ = json.Unmarshal(condJSON, &rule.Conditions)
	}
	if len(tuningJSON) > 0 {
		_ = json.Unmarshal(tuningJSON, &rule.Tuning)
	}
	return &rule, nil
}

// HitStat aggregates the recent waf_decisions attributed to one custom rule.
type HitStat struct {
	Count   int64     `json:"count"`
	LastHit time.Time `json:"last_hit"`
}

// HitStats returns 30-day hit counts per custom rule id for an app, from the
// match_detail prefix the detection pipeline stamps on custom-rule decisions
// ("custom_gui_rule:<id>" / "custom_script_rule:<id>"). Rules with no hits are
// simply absent from the map. Callers treat an error as "no stats available"
// and must not fail the listing on it. Only decisions of projectID's own
// agents count.
func (r *WafCustomRulesRepo) HitStats(ctx context.Context, projectID, appID string) (map[string]HitStat, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT d.match_detail, count(*), max(d.recorded_at)
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE d.app_id = $1 AND a.project_id = $2
		  AND d.analyze_method = 'custom_rule'
		  AND (d.match_detail LIKE 'custom_gui_rule:%' OR d.match_detail LIKE 'custom_script_rule:%')
		  AND d.recorded_at > now() - interval '30 days'
		GROUP BY d.match_detail
	`, appID, projectID)
	if err != nil {
		return map[string]HitStat{}, err
	}
	defer rows.Close()

	stats := map[string]HitStat{}
	for rows.Next() {
		var detail string
		var stat HitStat
		if err := rows.Scan(&detail, &stat.Count, &stat.LastHit); err != nil {
			return map[string]HitStat{}, err
		}
		idx := strings.LastIndex(detail, ":")
		if idx < 0 || idx == len(detail)-1 {
			continue
		}
		stats[detail[idx+1:]] = stat
	}
	if err := rows.Err(); err != nil {
		return map[string]HitStat{}, err
	}
	return stats, nil
}

func (r *WafCustomRulesRepo) Create(ctx context.Context, appID string, rule domain.CustomRule) (*domain.CustomRule, error) {
	condJSON, _ := json.Marshal(rule.Conditions)
	var tuningJSON []byte
	if rule.Tuning != nil {
		tuningJSON, _ = json.Marshal(rule.Tuning)
	}
	var out domain.CustomRule
	var outCondJSON, outTuningJSON []byte
	err := r.pool.QueryRow(ctx, `
		INSERT INTO waf_custom_rules
			(app_id, name, description, enabled, priority, mode, conditions, condition_logic, action, script, tuning)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING id, app_id, name, description, enabled, priority, mode,
		          conditions, condition_logic, action, script, tuning, created_at, updated_at
	`, appID, rule.Name, rule.Description, rule.Enabled, rule.Priority,
		rule.Mode, condJSON, rule.ConditionLogic, rule.Action, rule.Script, tuningJSON,
	).Scan(
		&out.ID, &out.AppID, &out.Name, &out.Description, &out.Enabled,
		&out.Priority, &out.Mode, &outCondJSON, &out.ConditionLogic,
		&out.Action, &out.Script, &outTuningJSON, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(outCondJSON) > 0 {
		_ = json.Unmarshal(outCondJSON, &out.Conditions)
	}
	if len(outTuningJSON) > 0 {
		_ = json.Unmarshal(outTuningJSON, &out.Tuning)
	}
	return &out, nil
}

func (r *WafCustomRulesRepo) Update(ctx context.Context, appID, ruleID string, rule domain.CustomRule) (*domain.CustomRule, error) {
	condJSON, _ := json.Marshal(rule.Conditions)
	var tuningJSON []byte
	if rule.Tuning != nil {
		tuningJSON, _ = json.Marshal(rule.Tuning)
	}
	var out domain.CustomRule
	var outCondJSON, outTuningJSON []byte
	err := r.pool.QueryRow(ctx, `
		UPDATE waf_custom_rules
		SET name=$3, description=$4, enabled=$5, priority=$6, mode=$7,
		    conditions=$8, condition_logic=$9, action=$10, script=$11, tuning=$12, updated_at=NOW()
		WHERE id=$1 AND app_id=$2
		RETURNING id, app_id, name, description, enabled, priority, mode,
		          conditions, condition_logic, action, script, tuning, created_at, updated_at
	`, ruleID, appID, rule.Name, rule.Description, rule.Enabled, rule.Priority,
		rule.Mode, condJSON, rule.ConditionLogic, rule.Action, rule.Script, tuningJSON,
	).Scan(
		&out.ID, &out.AppID, &out.Name, &out.Description, &out.Enabled,
		&out.Priority, &out.Mode, &outCondJSON, &out.ConditionLogic,
		&out.Action, &out.Script, &outTuningJSON, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(outCondJSON) > 0 {
		_ = json.Unmarshal(outCondJSON, &out.Conditions)
	}
	if len(outTuningJSON) > 0 {
		_ = json.Unmarshal(outTuningJSON, &out.Tuning)
	}
	return &out, nil
}

// Delete removes a rule of appID; deleted is false when no such rule exists
// (missing or another app's).
func (r *WafCustomRulesRepo) Delete(ctx context.Context, appID, ruleID string) (deleted bool, err error) {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM waf_custom_rules WHERE id=$1 AND app_id=$2`,
		ruleID, appID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
