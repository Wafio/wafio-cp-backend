package repository

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// DeliveryAgent is the agent row a certificate key may be sent to, as the database has it now.
type DeliveryAgent struct {
	Name, HostID string
}

// DeliveryAgent returns the WAF agent row of the project that the credential is bound to: the
// credential still exists, is bound to the host, kind waf and name of the row, the host is not
// revoked, and the agent said it serves TLS certificates. It returns pgx.ErrNoRows otherwise. The
// caller compares the name and the host with the binding its stream carries. This is checked at send
// time, because the stream resolved its agent row by name when it connected, and a credential can be
// deleted, a host revoked, or the row replaced, while the stream stays open. Revoking a host deletes
// its credentials, so the host check is a second layer.
func (r *TLSRepo) DeliveryAgent(ctx context.Context, projectID, credentialID, agentID string) (DeliveryAgent, error) {
	if !canonicalIDs(&projectID, &agentID) {
		return DeliveryAgent{}, pgx.ErrNoRows
	}
	var a DeliveryAgent
	err := r.pool.QueryRow(ctx, `SELECT ag.name, ag.host_id::text
		FROM agents ag
		JOIN hosts h ON h.id = ag.host_id AND h.project_id = ag.project_id AND h.revoked_at IS NULL AND h.status <> 'revoked'
		JOIN mtls_credentials c ON c.project_id = ag.project_id AND c.host_id IS NOT NULL AND c.host_id = ag.host_id
		     AND c.agent_kind = 'waf' AND c.agent_name = ag.name
		WHERE ag.id = $1 AND ag.project_id = $2 AND c.id::text = $3
		  AND ag.kind = 'waf' AND ag.deleted_at IS NULL AND ag.tls_certificates IS TRUE`,
		agentID, projectID, credentialID).Scan(&a.Name, &a.HostID)
	return a, err
}

// StatusPrior is what the database holds for an app when its agent reports on it: the stored status,
// if any. StatusPrior returns it only for an agent that may report, so reading it is also the
// authorization check of a status.
type StatusPrior struct {
	// Stored says whether a status row exists; the other fields are empty when it does not.
	Stored bool
	// Leaf is the leaf of the stored status, "" when it names none.
	Leaf                                                    string
	AgentID, Source, State, CertificateID, Error, RequestID string
	NextAttemptAt                                           *time.Time
	ReceivedAt                                              time.Time
}

// StatusPrior returns the stored status of the app and true when the app is enabled on this agent,
// in this project, in gateway mode with this source, and, for an acme report, the request id is the
// current one, and for an uploaded report the certificate is the one the app names as current. It
// returns false, and the caller drops the status without reading anything of it, otherwise.
func (r *TLSRepo) StatusPrior(ctx context.Context, projectID, agentID, appID, source, requestID, certificateID string) (StatusPrior, bool, error) {
	if !canonicalIDs(&projectID, &agentID, &appID) || (certificateID != "" && !canonicalIDs(&certificateID)) {
		return StatusPrior{}, false, nil
	}
	var p StatusPrior
	var received *time.Time
	err := r.pool.QueryRow(ctx, `SELECT s.app_id IS NOT NULL, COALESCE(s.leaf_sha256, ''), COALESCE(s.agent_id::text, ''), COALESCE(s.source, ''),
			COALESCE(s.state, ''), COALESCE(s.certificate_id::text, ''), COALESCE(s.error, ''), COALESCE(s.request_id, ''),
			s.next_attempt_at, s.received_at
		FROM apps a
		JOIN waf_agent_apps waa ON waa.app_id = a.id AND waa.enabled = TRUE AND waa.agent_id = $3
		JOIN agents ag ON ag.id = waa.agent_id AND ag.project_id = a.project_id AND ag.kind = 'waf' AND ag.deleted_at IS NULL
		LEFT JOIN app_tls_status s ON s.app_id = a.id AND s.project_id = a.project_id
		WHERE a.id = $1 AND a.project_id = $2 AND a.tls_mode = 'gateway' AND a.tls_source = $4::text
		  AND ($4::text <> 'acme' OR a.acme_request_id = $5::text)
		  AND ($4::text <> 'uploaded' OR a.tls_certificate_id = NULLIF($6::text, '')::uuid)`,
		appID, projectID, agentID, source, requestID, certificateID).
		Scan(&p.Stored, &p.Leaf, &p.AgentID, &p.Source, &p.State, &p.CertificateID, &p.Error, &p.RequestID, &p.NextAttemptAt, &received)
	if errors.Is(err, pgx.ErrNoRows) {
		return StatusPrior{}, false, nil
	}
	if err != nil {
		return StatusPrior{}, false, err
	}
	if received != nil {
		p.ReceivedAt = *received
	}
	return p, true, nil
}

// Unchanged says whether storing rep would change nothing that the dashboard shows: the same agent,
// state, source, certificate, leaf, request id, error and retry time, stored less than refresh ago.
// The caller then skips the write. The stored time is refreshed once it is that old, so it keeps
// telling when the agent last said the same thing.
func (p StatusPrior) Unchanged(rep TLSStatusReport, now time.Time, refresh time.Duration) bool {
	if !p.Stored || now.Sub(p.ReceivedAt) >= refresh {
		return false
	}
	sameTime := (p.NextAttemptAt == nil && rep.NextAttemptAt == nil) ||
		(p.NextAttemptAt != nil && rep.NextAttemptAt != nil && p.NextAttemptAt.Unix() == rep.NextAttemptAt.Unix())
	return p.AgentID == rep.AgentID && p.State == rep.State && p.Source == rep.Source && p.CertificateID == rep.CertificateID &&
		p.Leaf == rep.LeafSHA256 && p.RequestID == rep.RequestID && p.Error == cleanStatusError(rep.Error) && sameTime
}
