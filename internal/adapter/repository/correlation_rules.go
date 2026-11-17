// Correlation rule persistence: multi-stage attack chains.
// Built-ins are seeded per project and cannot be deleted — disable only,
// mirroring trace_detection_rules.
package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wafio/wafio-cp-backend/internal/application"
)

// ErrBuiltInCorrelation marks a delete attempt against a seeded chain (409 BUILTIN_RULE).
var ErrBuiltInCorrelation = errors.New("built-in correlation rules cannot be deleted, disable them instead")

// StoredCorrelationRule is the persisted shape (engine CorrelationRule + row meta).
type StoredCorrelationRule struct {
	ID          string                      `json:"id"`
	ProjectID   string                      `json:"project_id"`
	Name        string                      `json:"name"`
	Description string                      `json:"description"`
	Enabled     bool                        `json:"enabled"`
	BuiltIn     bool                        `json:"built_in"`
	Rule        application.CorrelationRule `json:"rule"`
	CreatedAt   time.Time                   `json:"created_at"`
	UpdatedAt   time.Time                   `json:"updated_at"`
}

type CorrelationRulesRepo struct {
	pool *pgxpool.Pool
}

func (r *CorrelationRulesRepo) List(ctx context.Context, projectID string) ([]StoredCorrelationRule, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, name, description, enabled, built_in, entity, max_span_ms, stages, created_at, updated_at
		FROM correlation_rules
		WHERE project_id = $1
		ORDER BY built_in DESC, created_at ASC`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list correlation rules: %w", err)
	}
	defer rows.Close()

	out := []StoredCorrelationRule{}
	for rows.Next() {
		var s StoredCorrelationRule
		var stagesJSON []byte
		var maxSpanMs int64
		if err := rows.Scan(&s.ID, &s.Name, &s.Description, &s.Enabled, &s.BuiltIn,
			&s.Rule.Entity, &maxSpanMs, &stagesJSON, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan correlation rule: %w", err)
		}
		s.ProjectID = projectID
		s.Rule.ID = s.ID
		s.Rule.Name = s.Name
		s.Rule.MaxSpan = time.Duration(maxSpanMs) * time.Millisecond
		if err := json.Unmarshal(stagesJSON, &s.Rule.Stages); err != nil {
			return nil, fmt.Errorf("decode stages for %s: %w", s.ID, err)
		}
		canonicalizeBuiltin(&s)
		out = append(out, s)
	}
	return out, rows.Err()
}

// EnabledRules returns engine-ready rules (built-ins included when enabled).
func (r *CorrelationRulesRepo) EnabledRules(ctx context.Context, projectID string) ([]*application.CorrelationRule, error) {
	stored, err := r.List(ctx, projectID)
	if err != nil {
		return nil, err
	}
	var out []*application.CorrelationRule
	for _, s := range stored {
		if s.Enabled {
			rule := s.Rule
			out = append(out, &rule)
		}
	}
	return out, nil
}

// EnabledCorrelationRulesByProject returns the enabled rules of every
// project that has stored correlation rows (an empty slice when all are
// disabled), for loading the correlation registry at startup
// (application.CorrelationRuleSource). Built-in rows map to the current
// built-in definition, as in List. A project with an undecodable row is
// left out, so it keeps the built-in chains, and the error is logged.
func (r *CorrelationRulesRepo) EnabledCorrelationRulesByProject(ctx context.Context) (map[string][]*application.CorrelationRule, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT c.project_id::text, c.id, c.name, c.enabled, c.built_in, c.entity, c.max_span_ms, c.stages
		FROM correlation_rules c
		JOIN projects p ON p.id = c.project_id
		ORDER BY c.project_id, c.built_in DESC, c.created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("list correlation rules: %w", err)
	}
	defer rows.Close()

	out := map[string][]*application.CorrelationRule{}
	broken := map[string]bool{}
	for rows.Next() {
		var s StoredCorrelationRule
		var stagesJSON []byte
		var maxSpanMs int64
		if err := rows.Scan(&s.ProjectID, &s.ID, &s.Name, &s.Enabled, &s.BuiltIn,
			&s.Rule.Entity, &maxSpanMs, &stagesJSON); err != nil {
			return nil, fmt.Errorf("scan correlation rule: %w", err)
		}
		if _, ok := out[s.ProjectID]; !ok {
			out[s.ProjectID] = []*application.CorrelationRule{}
		}
		s.Rule.ID = s.ID
		s.Rule.Name = s.Name
		s.Rule.MaxSpan = time.Duration(maxSpanMs) * time.Millisecond
		if err := json.Unmarshal(stagesJSON, &s.Rule.Stages); err != nil {
			log.Printf("[correlation] project %s rule %s: undecodable stages, project keeps built-in chains: %v", s.ProjectID, s.ID, err) //nolint:gosec // G706: ids and a decode error, no request data
			broken[s.ProjectID] = true
			continue
		}
		canonicalizeBuiltin(&s)
		if s.Enabled {
			rule := s.Rule
			out[s.ProjectID] = append(out[s.ProjectID], &rule)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list correlation rules: %w", err)
	}
	for id := range broken {
		delete(out, id)
	}
	return out, nil
}

func (r *CorrelationRulesRepo) Get(ctx context.Context, projectID, id string) (*StoredCorrelationRule, error) {
	var s StoredCorrelationRule
	var stagesJSON []byte
	var maxSpanMs int64
	err := r.pool.QueryRow(ctx, `
		SELECT id, name, description, enabled, built_in, entity, max_span_ms, stages, created_at, updated_at
		FROM correlation_rules
		WHERE project_id = $1 AND id = $2`, projectID, id).
		Scan(&s.ID, &s.Name, &s.Description, &s.Enabled, &s.BuiltIn,
			&s.Rule.Entity, &maxSpanMs, &stagesJSON, &s.CreatedAt, &s.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get correlation rule: %w", err)
	}
	s.ProjectID = projectID
	s.Rule.ID = s.ID
	s.Rule.Name = s.Name
	s.Rule.MaxSpan = time.Duration(maxSpanMs) * time.Millisecond
	if err := json.Unmarshal(stagesJSON, &s.Rule.Stages); err != nil {
		return nil, fmt.Errorf("decode stages: %w", err)
	}
	canonicalizeBuiltin(&s)
	return &s, nil
}

// canonicalizeBuiltin replaces a built-in row's seeded definition with the
// engine's current one (stages of a built-in are not editable, so the seeded
// copy only goes stale). Row ID, name, description and enabled stay.
func canonicalizeBuiltin(s *StoredCorrelationRule) {
	if !s.BuiltIn {
		return
	}
	c := application.CanonicalBuiltinCorrelationRule(s.Name)
	if c == nil {
		return
	}
	s.Rule.Entity = c.Entity
	s.Rule.MaxSpan = c.MaxSpan
	s.Rule.Stages = c.Stages
	s.Rule.Technique = c.Technique
	s.Rule.Tactic = c.Tactic
}

func (r *CorrelationRulesRepo) Create(ctx context.Context, projectID string, s *StoredCorrelationRule) error {
	stagesJSON, err := json.Marshal(s.Rule.Stages)
	if err != nil {
		return fmt.Errorf("encode stages: %w", err)
	}
	return r.pool.QueryRow(ctx, `
		INSERT INTO correlation_rules (project_id, name, description, enabled, built_in, entity, max_span_ms, stages)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at, updated_at`,
		projectID, s.Name, s.Description, s.Enabled, s.BuiltIn,
		s.Rule.Entity, s.Rule.MaxSpan.Milliseconds(), stagesJSON).
		Scan(&s.ID, &s.CreatedAt, &s.UpdatedAt)
}

func (r *CorrelationRulesRepo) Update(ctx context.Context, projectID, id string, s *StoredCorrelationRule) error {
	stagesJSON, err := json.Marshal(s.Rule.Stages)
	if err != nil {
		return fmt.Errorf("encode stages: %w", err)
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE correlation_rules
		SET name = $3, description = $4, enabled = $5, entity = $6, max_span_ms = $7, stages = $8, updated_at = now()
		WHERE project_id = $1 AND id = $2`,
		projectID, id, s.Name, s.Description, s.Enabled, s.Rule.Entity, s.Rule.MaxSpan.Milliseconds(), stagesJSON)
	if err != nil {
		return fmt.Errorf("update correlation rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// Delete removes a custom rule. Built-ins are rejected — disable them instead.
func (r *CorrelationRulesRepo) Delete(ctx context.Context, projectID, id string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM correlation_rules WHERE project_id = $1 AND id = $2 AND built_in = false`,
		projectID, id)
	if err != nil {
		return fmt.Errorf("delete correlation rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Distinguish "not found" from "built-in" for the 404 vs 409 mapping.
		var builtIn bool
		err := r.pool.QueryRow(ctx,
			`SELECT built_in FROM correlation_rules WHERE project_id = $1 AND id = $2`,
			projectID, id).Scan(&builtIn)
		if errors.Is(err, pgx.ErrNoRows) {
			return pgx.ErrNoRows
		}
		if err == nil && builtIn {
			return ErrBuiltInCorrelation
		}
		return pgx.ErrNoRows
	}
	return nil
}

// SeedBuiltins inserts the engine's built-in chains for a project (idempotent).
func (r *CorrelationRulesRepo) SeedBuiltins(ctx context.Context, projectID string) error {
	for _, rule := range application.BuiltinCorrelationRules() {
		stagesJSON, err := json.Marshal(rule.Stages)
		if err != nil {
			return fmt.Errorf("encode builtin stages: %w", err)
		}
		_, err = r.pool.Exec(ctx, `
			INSERT INTO correlation_rules (project_id, name, description, enabled, built_in, entity, max_span_ms, stages)
			VALUES ($1, $2, $3, true, true, $4, $5, $6)
			ON CONFLICT (project_id, name) DO NOTHING`,
			projectID, rule.Name, "Built-in chain", rule.Entity, rule.MaxSpan.Milliseconds(), stagesJSON)
		if err != nil {
			return fmt.Errorf("seed builtin correlation rule: %w", err)
		}
	}
	return nil
}

// EnsureBuiltins seeds the built-in chains for a project that has no
// correlation rule at all yet. Called at project creation and before the
// first rule write; reads never seed.
func (r *CorrelationRulesRepo) EnsureBuiltins(ctx context.Context, projectID string) error {
	var exists bool
	if err := r.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM correlation_rules WHERE project_id = $1)`, projectID,
	).Scan(&exists); err != nil {
		return fmt.Errorf("check correlation rules: %w", err)
	}
	if exists {
		return nil
	}
	return r.SeedBuiltins(ctx, projectID)
}

// SeedUnseededProjects seeds the built-in chains for every project without a
// correlation rule, and returns how many projects it seeded. Runs once at
// control-plane startup for projects created before seeding moved out of
// GET /correlation-rules.
func (r *CorrelationRulesRepo) SeedUnseededProjects(ctx context.Context) (int, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT p.id::text FROM projects p
		  WHERE NOT EXISTS (SELECT 1 FROM correlation_rules c WHERE c.project_id = p.id)`)
	if err != nil {
		return 0, fmt.Errorf("list unseeded projects: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan unseeded project: %w", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("list unseeded projects: %w", err)
	}
	seeded := 0
	for _, id := range ids {
		if err := r.SeedBuiltins(ctx, id); err != nil {
			return seeded, err
		}
		seeded++
	}
	return seeded, nil
}

func NewCorrelationRulesRepo(pool *pgxpool.Pool) *CorrelationRulesRepo {
	return &CorrelationRulesRepo{pool: pool}
}

var _ application.CorrelationRuleSource = (*CorrelationRulesRepo)(nil)
