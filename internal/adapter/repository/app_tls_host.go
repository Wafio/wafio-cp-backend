package repository

import (
	"context"
	"errors"
	"net/netip"

	"github.com/jackc/pgx/v5"
)

// AgentReportedAddresses returns the addresses the host of a WAF agent said it has: the public_ip and
// primary_ip of the host information the agent sends in its heartbeat (agents.host_info). It returns
// none for an agent that never sent host information, for an agent of another project, and for a
// value that is not an address. It is a hint for the dashboard, never a decision.
func (r *TLSRepo) AgentReportedAddresses(ctx context.Context, projectID, agentID string) ([]netip.Addr, error) {
	if !canonicalIDs(&projectID, &agentID) {
		return nil, nil
	}
	var public, primary string
	err := r.pool.QueryRow(ctx, `SELECT COALESCE(host_info->>'public_ip', ''), COALESCE(host_info->>'primary_ip', '')
		FROM agents WHERE id = $1 AND project_id = $2 AND kind = 'waf' AND deleted_at IS NULL`, agentID, projectID).Scan(&public, &primary)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, v := range []string{public, primary} {
		if a, err := netip.ParseAddr(v); err == nil {
			out = append(out, a.Unmap())
		}
	}
	return out, nil
}
