package repository

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MTLSCredential holds a provisioned client certificate for agent authentication.
type MTLSCredential struct {
	ID                    string
	ProjectID             string
	Name                  string
	ClientCertPEM         string
	CertFingerprintSHA256 string
	SecretHash            string
	CreatedAt             time.Time
	// HostID, AgentKind and AgentName bind a credential enrolled with a host
	// key (migration 000108) to one agent on one host; all empty for a
	// project-wide credential made on the Credentials page.
	HostID    string
	AgentKind string
	AgentName string
	// NotAfter mirrors the certificate's expiry for enrolled credentials
	// (nil for project-wide ones).
	NotAfter *time.Time
	// HostName is filled by ListAgentCredentials only.
	HostName string
}

// HostBound reports whether the credential was enrolled for one host.
func (c *MTLSCredential) HostBound() bool { return c != nil && c.HostID != "" }

// credentialColumns is the select (and RETURNING) list scanCredential reads.
const credentialColumns = `id, project_id, name, client_cert_pem, cert_fingerprint_sha256, COALESCE(secret_hash, ''), created_at,
	COALESCE(host_id::text, ''), COALESCE(agent_kind, ''), COALESCE(agent_name, ''), not_after`

type rowScanner interface{ Scan(dest ...any) error }

func scanCredential(row rowScanner, extra ...any) (MTLSCredential, error) {
	var c MTLSCredential
	dest := []any{&c.ID, &c.ProjectID, &c.Name, &c.ClientCertPEM, &c.CertFingerprintSHA256, &c.SecretHash, &c.CreatedAt,
		&c.HostID, &c.AgentKind, &c.AgentName, &c.NotAfter}
	err := row.Scan(append(dest, extra...)...)
	return c, err
}

func scanCredentials(rows pgx.Rows) ([]MTLSCredential, error) {
	defer rows.Close()
	out := []MTLSCredential{}
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// FingerprintFromPEM computes the SHA-256 fingerprint of the first certificate in pemBytes.
func FingerprintFromPEM(pemBytes []byte) string {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// AgentGRPCRepo handles persistence for the agent gRPC mTLS infrastructure
// (the CA used to sign client certs + provisioned credentials).
type AgentGRPCRepo struct {
	pool *pgxpool.Pool
}

func NewAgentGRPCRepo(pool *pgxpool.Pool) *AgentGRPCRepo { return &AgentGRPCRepo{pool: pool} }

// AgentGRPCCA is the CA cert+key used to sign per-agent client certs.
// Single global row when project_id IS NULL.
type AgentGRPCCA struct {
	ID        string
	CertPEM   string
	KeyPEM    string
	CreatedAt time.Time
	NotAfter  time.Time
}

var ErrAgentGRPCCANotFound = errors.New("agent grpc CA not found")

// GetGlobalCACertPEM returns only the global CA certificate (never its key),
// or ErrAgentGRPCCANotFound. It never creates the CA.
func (r *AgentGRPCRepo) GetGlobalCACertPEM(ctx context.Context) (string, error) {
	var certPEM string
	err := r.pool.QueryRow(ctx,
		`SELECT cert_pem FROM agent_grpc_ca WHERE project_id IS NULL ORDER BY created_at DESC LIMIT 1`,
	).Scan(&certPEM)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrAgentGRPCCANotFound
	}
	return certPEM, err
}

// GetGlobalCA returns the single global CA, or ErrAgentGRPCCANotFound.
func (r *AgentGRPCRepo) GetGlobalCA(ctx context.Context) (*AgentGRPCCA, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, cert_pem, key_pem, created_at, not_after
		   FROM agent_grpc_ca
		  WHERE project_id IS NULL
		  ORDER BY created_at DESC
		  LIMIT 1`,
	)
	var ca AgentGRPCCA
	if err := row.Scan(&ca.ID, &ca.CertPEM, &ca.KeyPEM, &ca.CreatedAt, &ca.NotAfter); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAgentGRPCCANotFound
		}
		return nil, err
	}
	return &ca, nil
}

// CreateGlobalCA inserts a new global CA row. Caller is expected to do this
// only once (the unique partial index enforces it).
func (r *AgentGRPCRepo) CreateGlobalCA(ctx context.Context, certPEM, keyPEM string, notAfter time.Time) (*AgentGRPCCA, error) {
	row := r.pool.QueryRow(ctx,
		`INSERT INTO agent_grpc_ca (project_id, cert_pem, key_pem, not_after)
		 VALUES (NULL, $1, $2, $3)
		 RETURNING id, cert_pem, key_pem, created_at, not_after`,
		certPEM, keyPEM, notAfter,
	)
	var ca AgentGRPCCA
	if err := row.Scan(&ca.ID, &ca.CertPEM, &ca.KeyPEM, &ca.CreatedAt, &ca.NotAfter); err != nil {
		return nil, err
	}
	return &ca, nil
}

// CreateAgentCredential inserts an mtls_credentials row for purpose='agent_grpc'.
// The cert PEM is the *client* cert (signed by the CA above); the private key
// is returned to the caller in the same response and never stored server-side.
func (r *AgentGRPCRepo) CreateAgentCredential(ctx context.Context, projectID, name, clientCertPEM string) (*MTLSCredential, error) {
	return createAgentCredential(ctx, r.pool, projectID, name, clientCertPEM)
}

// CreateAgentCredentialAudited stores the credential and the audit row that
// audit builds from it in one transaction: a credential is never created
// without its audit entry.
func (r *AgentGRPCRepo) CreateAgentCredentialAudited(ctx context.Context, projectID, name, clientCertPEM string, audit func(*MTLSCredential) AuditEvent) (*MTLSCredential, error) {
	var cred *MTLSCredential
	err := inTx(ctx, r.pool, func(tx pgx.Tx) error {
		c, err := createAgentCredential(ctx, tx, projectID, name, clientCertPEM)
		if err != nil {
			return err
		}
		cred = c
		return auditInTx(ctx, tx, audit(c))
	})
	if err != nil {
		return nil, err
	}
	return cred, nil
}

// DeleteAgentCredentialAudited deletes the project's credential and writes ev
// in the same transaction. deleted is false (nothing audited) when id is not
// an agent credential of the project. A failed audit write does not block
// the revoke (auditRemovalInTx).
func (r *AgentGRPCRepo) DeleteAgentCredentialAudited(ctx context.Context, id, projectID string, ev AuditEvent) (deleted bool, err error) {
	err = inTx(ctx, r.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM mtls_credentials
			  WHERE id = $1 AND project_id = $2 AND purpose = 'agent_grpc'`,
			id, projectID)
		if err != nil {
			return err
		}
		if deleted = tag.RowsAffected() > 0; !deleted {
			return nil
		}
		return auditRemovalEventInTx(ctx, tx, ev)
	})
	return deleted, err
}

func createAgentCredential(ctx context.Context, q dbtx, projectID, name, clientCertPEM string) (*MTLSCredential, error) {
	fp := FingerprintFromPEM([]byte(clientCertPEM))
	row := q.QueryRow(ctx,
		`INSERT INTO mtls_credentials (project_id, name, client_cert_pem, cert_fingerprint_sha256, purpose)
		 VALUES ($1, $2, $3, $4, 'agent_grpc')
		 RETURNING `+credentialColumns,
		projectID, name, clientCertPEM, fp,
	)
	c, err := scanCredential(row)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// LookupAgentCredentialByFingerprint resolves the project_id (and credential
// metadata) for a presented client cert. Used by the gRPC mTLS interceptor.
func (r *AgentGRPCRepo) LookupAgentCredentialByFingerprint(ctx context.Context, fp string) (*MTLSCredential, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+credentialColumns+`
		   FROM mtls_credentials
		  WHERE cert_fingerprint_sha256 = $1
		    AND purpose = 'agent_grpc'`,
		fp,
	)
	c, err := scanCredential(row)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ListAgentCredentials lists agent_grpc credentials for a project (no key),
// with the name of the host an enrolled credential is bound to.
func (r *AgentGRPCRepo) ListAgentCredentials(ctx context.Context, projectID string) ([]MTLSCredential, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT c.id, c.project_id, c.name, c.client_cert_pem, c.cert_fingerprint_sha256, COALESCE(c.secret_hash, ''), c.created_at,
		        COALESCE(c.host_id::text, ''), COALESCE(c.agent_kind, ''), COALESCE(c.agent_name, ''), c.not_after,
		        COALESCE(h.name, '')
		   FROM mtls_credentials c
		   LEFT JOIN hosts h ON h.id = c.host_id AND h.project_id = c.project_id
		  WHERE c.project_id = $1 AND c.purpose = 'agent_grpc'
		  ORDER BY c.created_at DESC`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MTLSCredential{}
	for rows.Next() {
		var hostName string
		c, err := scanCredential(rows, &hostName)
		if err != nil {
			return nil, err
		}
		c.HostName = hostName
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListAllAgentCredentials returns every agent_grpc credential across all
// projects. Internal use only (cert-expiry monitor) — never exposed via an
// HTTP route, which remain project-scoped.
func (r *AgentGRPCRepo) ListAllAgentCredentials(ctx context.Context) ([]MTLSCredential, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+credentialColumns+`
		   FROM mtls_credentials
		  WHERE purpose = 'agent_grpc'`)
	if err != nil {
		return nil, err
	}
	return scanCredentials(rows)
}

// DeleteAgentCredential revokes an agent gRPC credential of projectID. It
// reports whether a row was deleted: false means the id does not exist or
// belongs to another project.
func (r *AgentGRPCRepo) DeleteAgentCredential(ctx context.Context, id, projectID string) (bool, error) {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM mtls_credentials
		  WHERE id = $1 AND project_id = $2 AND purpose = 'agent_grpc'`,
		id, projectID,
	)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
