package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Project struct {
	EffectiveRole string
	ID            string
	UserID        string
	Name          string
	Code          string
	Description   string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type ProjectConfig struct {
	ProjectID   string
	RulesJSON   []byte
	Sensitivity int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type ProjectRepo struct {
	pool *pgxpool.Pool
	// owners caches project -> owning account for per-account fairness
	// (OwnerOf); deletes drop the entry.
	owners projectOwnerCache
}

func (p *ProjectRepo) Create(ctx context.Context, userID, name, code, description string) (*Project, error) {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	row := tx.QueryRow(ctx,
		`INSERT INTO projects (user_id, name, code, description) VALUES ($1, $2, $3, $4)
		 RETURNING id, user_id, name, code, description, created_at, updated_at`,
		userID, name, code, description,
	)
	var proj Project
	if err := row.Scan(&proj.ID, &proj.UserID, &proj.Name, &proj.Code, &proj.Description, &proj.CreatedAt, &proj.UpdatedAt); err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, 'owner')`,
		proj.ID, userID,
	)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	p.RememberOwner(proj.ID, proj.UserID)
	return &proj, nil
}

func (p *ProjectRepo) GetByID(ctx context.Context, id string) (*Project, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT id, user_id, name, code, description, created_at, updated_at FROM projects WHERE id = $1`,
		id,
	)
	var proj Project
	err := row.Scan(&proj.ID, &proj.UserID, &proj.Name, &proj.Code, &proj.Description, &proj.CreatedAt, &proj.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &proj, nil
}

func (p *ProjectRepo) Update(ctx context.Context, id, name, description string) error {
	result, err := p.pool.Exec(ctx,
		`UPDATE projects SET name = $1, description = $2, updated_at = NOW() WHERE id = $3`,
		name, description, id,
	)
	if err == nil && result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return err
}

func (p *ProjectRepo) Delete(ctx context.Context, id, userID string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM projects WHERE id = $1 AND user_id = $2`, id, userID)
	p.ForgetOwner(id)
	return err
}

func (p *ProjectRepo) DeleteByID(ctx context.Context, id string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM projects WHERE id = $1`, id)
	p.ForgetOwner(id)
	return err
}

// DeleteAudited deletes the project and records ev in system_audit in one
// transaction. The project's own audit log (agent_audit) is deleted with it
// by ON DELETE CASCADE, so a project-scoped "project.deleted" row could never
// survive; system_audit does. deleted is false when no project had id.
// A failed audit write does not block the delete (auditRemovalInTx).
func (p *ProjectRepo) DeleteAudited(ctx context.Context, id string, ev SystemAuditEvent) (deleted bool, err error) {
	err = inTx(ctx, p.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM projects WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if deleted = tag.RowsAffected() > 0; !deleted {
			return nil
		}
		return auditRemovalInTx(ctx, tx, "system_audit", ev.Action, ev, func(q dbtx) error { return insertSystemAudit(ctx, q, ev) })
	})
	if deleted {
		p.ForgetOwner(id)
	}
	return deleted, err
}

// ListAllIDs returns all project IDs. Used by background cache warmers.
func (p *ProjectRepo) ListAllIDs(ctx context.Context) ([]string, error) {
	rows, err := p.pool.Query(ctx, `SELECT id FROM projects`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ListIDsOwnedBy returns the IDs of the projects userID owns: the ones a
// delete of that user cascades away.
func (p *ProjectRepo) ListIDsOwnedBy(ctx context.Context, userID string) ([]string, error) {
	rows, err := p.pool.Query(ctx, `SELECT id FROM projects WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ListForUser returns projects visible to the user.
// If isAdmin is true, all projects are returned (with total count).
// Otherwise, only projects the user is a member of are returned.
func (p *ProjectRepo) ListForUser(ctx context.Context, userID string, isAdmin bool, limit, offset int) ([]Project, int, error) {
	var total int
	var rows interface {
		Next() bool
		Scan(...any) error
		Close()
		Err() error
	}

	if isAdmin {
		if err := p.pool.QueryRow(ctx, `SELECT COUNT(*) FROM projects`).Scan(&total); err != nil {
			return nil, 0, err
		}
		r, err := p.pool.Query(ctx, //nolint:rowserrcheck // assigned to rows; checked at the return
			`SELECT id, user_id, name, code, description, created_at, updated_at, 'owner' FROM projects ORDER BY created_at DESC,id LIMIT $1 OFFSET $2`,
			limit, offset,
		)
		if err != nil {
			return nil, 0, err
		}
		rows = r
	} else {
		if err := p.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM projects p JOIN project_members pm ON pm.project_id = p.id WHERE pm.user_id = $1`,
			userID,
		).Scan(&total); err != nil {
			return nil, 0, err
		}
		r, err := p.pool.Query(ctx, //nolint:rowserrcheck // assigned to rows; checked at the return
			`SELECT p.id, p.user_id, p.name, p.code, p.description, p.created_at, p.updated_at, pm.role
			 FROM projects p JOIN project_members pm ON pm.project_id = p.id
			 WHERE pm.user_id = $1 ORDER BY p.created_at DESC,p.id LIMIT $2 OFFSET $3`,
			userID, limit, offset,
		)
		if err != nil {
			return nil, 0, err
		}
		rows = r
	}
	defer rows.Close()
	list := []Project{}
	for rows.Next() {
		var proj Project
		if err := rows.Scan(&proj.ID, &proj.UserID, &proj.Name, &proj.Code, &proj.Description, &proj.CreatedAt, &proj.UpdatedAt, &proj.EffectiveRole); err != nil {
			return nil, 0, err
		}
		list = append(list, proj)
	}
	return list, total, rows.Err()
}

func (p *ProjectRepo) GetConfig(ctx context.Context, projectID string) (*ProjectConfig, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT project_id, rules_json, sensitivity, created_at, updated_at FROM project_configs WHERE project_id = $1`,
		projectID,
	)
	var cfg ProjectConfig
	err := row.Scan(&cfg.ProjectID, &cfg.RulesJSON, &cfg.Sensitivity, &cfg.CreatedAt, &cfg.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (p *ProjectRepo) UpsertConfig(ctx context.Context, projectID string, rulesJSON []byte, sensitivity int) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO project_configs (project_id, rules_json, sensitivity) VALUES ($1, $2, $3)
		 ON CONFLICT (project_id) DO UPDATE SET rules_json = $2, sensitivity = $3, updated_at = NOW()`,
		projectID, rulesJSON, sensitivity,
	)
	return err
}
