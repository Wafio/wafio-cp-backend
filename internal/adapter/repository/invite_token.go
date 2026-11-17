package repository

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type InviteToken struct {
	Token     string
	Email     string
	CreatedBy string
	ProjectID string
	Role      string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

type InviteTokenRepo struct {
	pool *pgxpool.Pool
}

func (r *InviteTokenRepo) Create(ctx context.Context, token, email, createdBy, projectID, role string, expiresAt time.Time) error {
	if role == "" {
		role = "member"
	}
	_, err := r.pool.Exec(ctx,
		`INSERT INTO invite_tokens (token, email, created_by, project_id, role, expires_at) VALUES ($1, $2, $3, NULLIF($4, '')::uuid, $5, $6)`,
		token, email, createdBy, projectID, role, expiresAt,
	)
	return err
}

func (r *InviteTokenRepo) CreateForProject(ctx context.Context, token, email, createdBy, projectID, role string, expiresAt time.Time) error {
	return r.Create(ctx, token, email, createdBy, projectID, role, expiresAt)
}

func (r *InviteTokenRepo) GetByToken(ctx context.Context, token string) (*InviteToken, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT token, email, created_by, COALESCE(project_id::text, ''), role, expires_at, used_at, created_at FROM invite_tokens WHERE token = $1`,
		token,
	)
	var it InviteToken
	if err := row.Scan(&it.Token, &it.Email, &it.CreatedBy, &it.ProjectID, &it.Role, &it.ExpiresAt, &it.UsedAt, &it.CreatedAt); err != nil {
		return nil, err
	}
	return &it, nil
}

// ErrInviteUnavailable: the token does not exist, is used, expired, or (for
// AcceptProject) is not a project invite. Of two concurrent redemptions of
// one token exactly one succeeds; the other gets this error.
var ErrInviteUnavailable = errors.New("invite token is invalid, used or expired")

// claimInvite marks the token used, atomically and only when it is still
// unused and unexpired, and returns the invite as it was claimed.
func claimInvite(ctx context.Context, tx pgx.Tx, token string, projectOnly bool) (*InviteToken, error) {
	var it InviteToken
	err := tx.QueryRow(ctx,
		`UPDATE invite_tokens SET used_at = NOW()
		  WHERE token = $1 AND used_at IS NULL AND expires_at > NOW()
		    AND ($2 = false OR project_id IS NOT NULL)
		  RETURNING token, email, created_by, COALESCE(project_id::text, ''), role, expires_at, used_at, created_at`,
		token, projectOnly,
	).Scan(&it.Token, &it.Email, &it.CreatedBy, &it.ProjectID, &it.Role, &it.ExpiresAt, &it.UsedAt, &it.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInviteUnavailable
	}
	if err != nil {
		return nil, err
	}
	if it.Role == "" {
		it.Role = "member"
	}
	return &it, nil
}

// InviteRegistration is a registration by invite token.
type InviteRegistration struct {
	Token        string
	PasswordHash string
	Name         string
	// ResolveEmail receives the invite's email ("" for an open admin
	// invite) and returns the account email, or an error that aborts the
	// registration (e.g. a mismatch with the invited address).
	ResolveEmail func(inviteEmail string) (string, error)
	// Audit builds the audit rows for the new account; the project row is
	// written when the invite seats the user in a project, the system row
	// otherwise.
	Audit func(user *User, invite *InviteToken) (AuditEvent, SystemAuditEvent)
}

// RegisterWithInvite claims the invite, creates the user, seats it in the
// invite's project and writes the audit row, all in one transaction.
// The claim comes first: two parallel registrations with one token
// yield exactly one account; the other gets ErrInviteUnavailable. When user
// creation fails (e.g. the email is taken) the invite stays unused.
func (r *InviteTokenRepo) RegisterWithInvite(ctx context.Context, reg InviteRegistration) (*User, *InviteToken, error) {
	var (
		user   *User
		invite *InviteToken
	)
	err := inTx(ctx, r.pool, func(tx pgx.Tx) error {
		it, err := claimInvite(ctx, tx, reg.Token, false)
		if err != nil {
			return err
		}
		email, err := reg.ResolveEmail(it.Email)
		if err != nil {
			return err
		}
		u, err := insertUser(ctx, tx, email, reg.PasswordHash, reg.Name, "user")
		if err != nil {
			return err
		}
		user, invite = u, it
		projectEv, systemEv := reg.Audit(u, it)
		if it.ProjectID == "" {
			return noteAuditFailure("system_audit", systemEv.Action, insertSystemAudit(ctx, tx, systemEv))
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
			it.ProjectID, u.ID, it.Role); err != nil {
			return err
		}
		projectEv.ProjectID = it.ProjectID
		return auditInTx(ctx, tx, projectEv)
	})
	if err != nil {
		return nil, nil, err
	}
	return user, invite, nil
}

// AcceptProjectInvite claims a project invite for an existing user, adds the
// membership and writes the audit row in one transaction. check runs on the
// claimed invite (e.g. the invited-email match) and aborts on error. joined
// is false when the user already was a member (the invite is still spent,
// nothing is audited).
func (r *InviteTokenRepo) AcceptProjectInvite(ctx context.Context, token, userID string, check func(*InviteToken) error, audit func(*InviteToken) AuditEvent) (invite *InviteToken, joined bool, err error) {
	err = inTx(ctx, r.pool, func(tx pgx.Tx) error {
		it, err := claimInvite(ctx, tx, token, true)
		if err != nil {
			return err
		}
		if err := check(it); err != nil {
			return err
		}
		invite = it
		tag, err := tx.Exec(ctx,
			`INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
			it.ProjectID, userID, it.Role)
		if err != nil {
			return err
		}
		if joined = tag.RowsAffected() == 1; !joined {
			return nil
		}
		ev := audit(it)
		ev.ProjectID = it.ProjectID
		return auditInTx(ctx, tx, ev)
	})
	if err != nil {
		return nil, false, err
	}
	return invite, joined, nil
}

// Consume marks an invite token as used by setting used_at = NOW().
// Request paths redeem through RegisterWithInvite / AcceptProjectInvite,
// which claim the token atomically.
func (r *InviteTokenRepo) Consume(ctx context.Context, token string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE invite_tokens SET used_at = NOW() WHERE token = $1`,
		token,
	)
	return err
}

func (r *InviteTokenRepo) List(ctx context.Context) ([]InviteToken, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT token, email, created_by, COALESCE(project_id::text, ''), role, expires_at, used_at, created_at FROM invite_tokens ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []InviteToken{}
	for rows.Next() {
		var it InviteToken
		if err := rows.Scan(&it.Token, &it.Email, &it.CreatedBy, &it.ProjectID, &it.Role, &it.ExpiresAt, &it.UsedAt, &it.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, it)
	}
	return list, rows.Err()
}

func (r *InviteTokenRepo) Delete(ctx context.Context, token string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM invite_tokens WHERE token = $1`, token)
	return err
}

func (r *InviteTokenRepo) ListPendingProject(ctx context.Context, projectID string, limit, offset int) ([]InviteToken, int, error) {
	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM invite_tokens WHERE project_id=$1 AND used_at IS NULL AND expires_at>now()`, projectID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.pool.Query(ctx, `SELECT token,email,created_by,project_id::text,role,expires_at,used_at,created_at FROM invite_tokens WHERE project_id=$1 AND used_at IS NULL AND expires_at>now() ORDER BY created_at DESC,token LIMIT $2 OFFSET $3`, projectID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	list := []InviteToken{}
	for rows.Next() {
		var it InviteToken
		if err := rows.Scan(&it.Token, &it.Email, &it.CreatedBy, &it.ProjectID, &it.Role, &it.ExpiresAt, &it.UsedAt, &it.CreatedAt); err != nil {
			return nil, 0, err
		}
		list = append(list, it)
	}
	return list, total, rows.Err()
}

func (r *InviteTokenRepo) DeleteProject(ctx context.Context, projectID, token string) (bool, error) {
	result, err := r.pool.Exec(ctx, `DELETE FROM invite_tokens WHERE project_id=$1 AND token=$2 AND used_at IS NULL`, projectID, token)
	return result.RowsAffected() == 1, err
}
