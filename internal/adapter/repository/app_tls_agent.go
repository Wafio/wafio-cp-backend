package repository

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// DeliveryAgent is the agent row a certificate key may be sent to, as the database has it now.
type DeliveryAgent struct {
	Name, HostID string
}

// DeliveryAgent returns the WAF agent row of the project that the credential is bound to: the
// credential still exists, is bound to the host, kind waf and name of the row, and the agent said it
// serves TLS certificates. It returns pgx.ErrNoRows otherwise. The caller compares the name and the
// host with the binding its stream carries. This is checked at send time, because the stream
// resolved its agent row by name when it connected, and a credential can be deleted, or the row
// replaced, while the stream stays open.
func (r *TLSRepo) DeliveryAgent(ctx context.Context, projectID, credentialID, agentID string) (DeliveryAgent, error) {
	if !canonicalIDs(&projectID, &agentID) {
		return DeliveryAgent{}, pgx.ErrNoRows
	}
	var a DeliveryAgent
	err := r.pool.QueryRow(ctx, `SELECT ag.name, ag.host_id::text
		FROM agents ag
		JOIN mtls_credentials c ON c.project_id = ag.project_id AND c.host_id IS NOT NULL AND c.host_id = ag.host_id
		     AND c.agent_kind = 'waf' AND c.agent_name = ag.name
		WHERE ag.id = $1 AND ag.project_id = $2 AND c.id::text = $3
		  AND ag.kind = 'waf' AND ag.deleted_at IS NULL AND ag.tls_certificates IS TRUE`,
		agentID, projectID, credentialID).Scan(&a.Name, &a.HostID)
	return a, err
}

// TLSStatusLeaf returns the leaf the stored status of the application reports, "" when there is no
// status row or it names no leaf. The caller parses the chain of a new report only when its leaf is
// another one.
func (r *TLSRepo) TLSStatusLeaf(ctx context.Context, projectID, appID string) (string, error) {
	if !canonicalIDs(&projectID, &appID) {
		return "", nil
	}
	var leaf string
	err := r.pool.QueryRow(ctx, `SELECT leaf_sha256 FROM app_tls_status WHERE app_id = $1 AND project_id = $2`, appID, projectID).Scan(&leaf)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return leaf, err
}
