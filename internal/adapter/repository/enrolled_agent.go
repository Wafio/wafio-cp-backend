package repository

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// ErrAgentNameConflict: the agent name is used in the project by another
// agent row than the enrolled identity on its host (another host, no host,
// or the other kind), so a credential enrolled for this host cannot take it.
var ErrAgentNameConflict = errors.New("agent name used by another agent of the project")

// BindEnrolledAgent resolves the agent row a host-bound credential (migration
// 000108) connects as: the row of that kind and name on hostID, or a new row
// under the host when the project has no agent of that name. Any other row
// of the name -- on another host, on no host, or of the other kind -- is
// ErrAgentNameConflict: an enrolled credential never adopts or speaks for an
// agent it was not issued for (an unattached row may belong to another
// machine and carries that agent's WAF bundle), and agents are looked up by
// name alone after Hello, so the name must be unambiguous. kind is "host"
// (matches the legacy "ebpf" rows too) or "waf". Scoped by project_id.
func (r *EBPFRepo) BindEnrolledAgent(ctx context.Context, projectID, hostID, kind, name string) (string, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, COALESCE(host_id::text, ''), `+enrollAgentKindSQL+`
		  FROM agents
		 WHERE project_id = $1 AND deleted_at IS NULL AND name = $2
		 ORDER BY last_seen DESC NULLS LAST`,
		projectID, name)
	if err != nil {
		return "", err
	}
	type row struct{ id, host, kind string }
	var found []row
	for rows.Next() {
		var rw row
		if err := rows.Scan(&rw.id, &rw.host, &rw.kind); err != nil {
			rows.Close()
			return "", err
		}
		found = append(found, rw)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", err
	}
	own := ""
	for _, rw := range found {
		if rw.host != hostID || rw.kind != kind {
			return "", ErrAgentNameConflict
		}
		if own == "" {
			own = rw.id
		}
	}
	if own != "" {
		return own, nil
	}
	var userID string
	err = r.pool.QueryRow(ctx,
		`SELECT user_id FROM hosts WHERE id = $1 AND project_id = $2 AND revoked_at IS NULL`,
		hostID, projectID).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrHostKeyInvalid
	}
	if err != nil {
		return "", err
	}
	return r.UpsertAgentForHost(ctx, hostID, userID, projectID, kind, name)
}
