package repository

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ProjectMember struct {
	ID        string
	ProjectID string
	UserID    string
	UserEmail string
	UserName  string
	Role      string // "owner" | "member"
	CreatedAt time.Time
}

type ProjectMemberRepo struct {
	pool *pgxpool.Pool
}

// Add adds a user as a member of a project. No-ops if already exists.
func (r *ProjectMemberRepo) Add(ctx context.Context, projectID, userID, role string) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		projectID, userID, role,
	)
	return err
}

// Remove removes a user from a project.
func (r *ProjectMemberRepo) Remove(ctx context.Context, projectID, userID string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM project_members WHERE project_id = $1 AND user_id = $2`,
		projectID, userID,
	)
	return err
}

// List returns all members of a project, joined with user email+name.
func (r *ProjectMemberRepo) List(ctx context.Context, projectID string) ([]ProjectMember, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT pm.id, pm.project_id, pm.user_id, u.email, COALESCE(u.name, ''), pm.role, pm.created_at
		 FROM project_members pm
		 JOIN users u ON u.id = pm.user_id
		 WHERE pm.project_id = $1
		 ORDER BY pm.created_at ASC`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []ProjectMember{}
	for rows.Next() {
		var m ProjectMember
		if err := rows.Scan(&m.ID, &m.ProjectID, &m.UserID, &m.UserEmail, &m.UserName, &m.Role, &m.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, m)
	}
	return list, rows.Err()
}

// GetRole returns the role of a user in a project, or "" if not a member.
func (r *ProjectMemberRepo) GetRole(ctx context.Context, projectID, userID string) (string, error) {
	var role string
	err := r.pool.QueryRow(ctx,
		`SELECT role FROM project_members WHERE project_id = $1 AND user_id = $2`,
		projectID, userID,
	).Scan(&role)
	if err != nil {
		return "", nil
	}
	return role, nil
}

// UpdateRole changes the role of an existing member. It has no last-owner
// guard and writes no audit row; request paths use UpdateRoleAudited.
func (r *ProjectMemberRepo) UpdateRole(ctx context.Context, projectID, userID, role string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE project_members SET role = $1 WHERE project_id = $2 AND user_id = $3`,
		role, projectID, userID,
	)
	return err
}

var (
	// ErrMemberNotFound: the user is not a member of the project.
	ErrMemberNotFound = errors.New("project member not found")
	// ErrLastOwner: the change would leave the project without an owner.
	ErrLastOwner = errors.New("project must keep at least one owner")
)

// inTx runs fn in one transaction and commits when fn returns nil.
func inTx(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// auditInTx writes ev inside tx; a failure is counted like any failed audit
// write and rolls the mutation back with it.
func auditInTx(ctx context.Context, tx pgx.Tx, ev AuditEvent) error {
	return noteAuditFailure("agent_audit", ev.Action, insertAudit(ctx, tx, ev))
}

// auditRemovalInTx writes the audit row of a removal (credential revoke,
// member removal or demotion, project delete) inside tx under a savepoint.
// A removal must not be blocked by an audit outage: when the write fails the
// savepoint is rolled back, the full event is logged at error level and
// counted (AuditWriteFailures), and the removal still commits. Grants keep
// auditInTx, which fails the mutation with its audit row.
func auditRemovalInTx(ctx context.Context, tx pgx.Tx, table, action string, event any, write func(dbtx) error) error {
	sp, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	if werr := write(sp); werr != nil {
		if rerr := sp.Rollback(ctx); rerr != nil {
			return rerr
		}
		auditWriteFailures.Add(1)
		slog.Error("audit_write_failed", "table", table, "action", action,
			"mutation", "committed_without_audit", "event", event, "err", werr)
		return nil
	}
	return sp.Commit(ctx)
}

// roleRank orders project roles; unknown roles rank 0.
func roleRank(role string) int {
	switch role {
	case "viewer":
		return 1
	case "member":
		return 2
	case "owner":
		return 3
	}
	return 0
}

// lockMembers loads every membership row of the project under FOR UPDATE, so
// two concurrent owner demotions or removals cannot each see "another owner
// remains" and together leave none.
func lockMembers(ctx context.Context, tx pgx.Tx, projectID string) (roles map[string]string, owners int, err error) {
	rows, err := tx.Query(ctx,
		`SELECT user_id::text, role FROM project_members WHERE project_id = $1 FOR UPDATE`, projectID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	roles = map[string]string{}
	for rows.Next() {
		var uid, role string
		if err := rows.Scan(&uid, &role); err != nil {
			return nil, 0, err
		}
		roles[uid] = role
		if role == "owner" {
			owners++
		}
	}
	return roles, owners, rows.Err()
}

// AddAudited adds a member and writes ev in the same transaction. added is
// false (and nothing is audited) when the user already was a member.
func (r *ProjectMemberRepo) AddAudited(ctx context.Context, projectID, userID, role string, ev AuditEvent) (added bool, err error) {
	err = inTx(ctx, r.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
			projectID, userID, role)
		if err != nil {
			return err
		}
		if added = tag.RowsAffected() == 1; !added {
			return nil
		}
		return auditInTx(ctx, tx, ev)
	})
	return added, err
}

// UpdateRoleAudited changes a member's role and writes ev (with the previous
// role added as metadata "previous_role") in the same transaction.
// ErrMemberNotFound when the user is not a member; ErrLastOwner when the
// change would demote the project's only owner. A demotion commits even
// when its audit write fails (auditRemovalInTx); a promotion does not.
// Setting the role the member already has changes nothing and writes no
// audit row.
func (r *ProjectMemberRepo) UpdateRoleAudited(ctx context.Context, projectID, userID, role string, ev AuditEvent) error {
	return inTx(ctx, r.pool, func(tx pgx.Tx) error {
		roles, owners, err := lockMembers(ctx, tx, projectID)
		if err != nil {
			return err
		}
		current, ok := roles[userID]
		switch {
		case !ok:
			return ErrMemberNotFound
		case current == role:
			return nil
		case current == "owner" && owners <= 1:
			return ErrLastOwner
		}
		if _, err := tx.Exec(ctx,
			`UPDATE project_members SET role = $1 WHERE project_id = $2 AND user_id = $3`,
			role, projectID, userID); err != nil {
			return err
		}
		ev.MetadataJSON = withMeta(ev.MetadataJSON, "previous_role", current)
		if roleRank(role) < roleRank(current) {
			// A demotion removes access: an audit outage must not block it.
			return auditRemovalEventInTx(ctx, tx, ev)
		}
		return auditInTx(ctx, tx, ev)
	})
}

func auditRemovalEventInTx(ctx context.Context, tx pgx.Tx, ev AuditEvent) error {
	return auditRemovalInTx(ctx, tx, "agent_audit", ev.Action, ev, func(q dbtx) error { return insertAudit(ctx, q, ev) })
}

// RemoveAudited removes a member and writes ev (with metadata "role" = the
// removed role) in the same transaction. ErrMemberNotFound when the user is
// not a member; ErrLastOwner when it is the project's only owner. A failed audit
// write does not block the removal (auditRemovalInTx).
func (r *ProjectMemberRepo) RemoveAudited(ctx context.Context, projectID, userID string, ev AuditEvent) error {
	return inTx(ctx, r.pool, func(tx pgx.Tx) error {
		roles, owners, err := lockMembers(ctx, tx, projectID)
		if err != nil {
			return err
		}
		current, ok := roles[userID]
		if !ok {
			return ErrMemberNotFound
		}
		if current == "owner" && owners <= 1 {
			return ErrLastOwner
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM project_members WHERE project_id = $1 AND user_id = $2`,
			projectID, userID); err != nil {
			return err
		}
		ev.MetadataJSON = withMeta(ev.MetadataJSON, "role", current)
		return auditRemovalEventInTx(ctx, tx, ev)
	})
}

func withMeta(meta map[string]any, key string, value any) map[string]any {
	if meta == nil {
		meta = map[string]any{}
	}
	meta[key] = value
	return meta
}
