package repository

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// AuditHostEnrollRefused records an enrollment refused although its host key
// verified (window closed, credential limit, agent name of another host): a
// valid key used outside its window is a sign the key leaked.
const AuditHostEnrollRefused = "host.enroll_refused"

// HostEnrollRepo implements domain.HostEnrollStore (host-key enrollment,
// migration 000108).
type HostEnrollRepo struct {
	pool *pgxpool.Pool
	host *HostRepo
	grpc *AgentGRPCRepo
}

var _ domain.HostEnrollStore = (*HostEnrollRepo)(nil)

// VerifyCurrentHostKey: see domain.HostEnrollStore.
func (r *HostEnrollRepo) VerifyCurrentHostKey(ctx context.Context, raw string) (*domain.Host, error) {
	return r.host.VerifyCurrentKey(ctx, raw)
}

// AgentCA: see domain.HostEnrollStore.
func (r *HostEnrollRepo) AgentCA(ctx context.Context) (string, string, error) {
	ca, err := r.grpc.GetGlobalCA(ctx)
	if errors.Is(err, ErrAgentGRPCCANotFound) {
		return "", "", domain.ErrEnrollUnavailable
	}
	if err != nil {
		return "", "", err
	}
	return ca.CertPEM, ca.KeyPEM, nil
}

// enrollAgentKindSQL maps agents.kind to the credential kinds: 'waf' (or a
// legacy NULL) is a WAF agent, 'host' and the legacy 'ebpf' a host agent.
const enrollAgentKindSQL = `CASE WHEN COALESCE(kind, 'waf') = 'waf' THEN 'waf' ELSE 'host' END`

// IssueHostCredential: see domain.HostEnrollStore. One transaction:
//
//  1. lock the host row (FOR UPDATE): a concurrent revoke or delete either
//     waits for this commit (and then deletes the new credential) or has
//     committed and the host reads revoked;
//  2. the verified key must still be the current key, and the enrollment
//     window must be open;
//  3. the agent name must be used by nothing in the project but this
//     identity (kind + name) on this host;
//  4. an identity enrolled since the window opened accepts only the same
//     public key (ErrEnrollUsed otherwise); when that credential is not
//     expired and its certificate still chains to the current agent CA
//     (in.CACertPEM), it is returned unchanged (Replayed) and the
//     transaction ends here: nothing signed, deleted, inserted, audited or
//     superseded, so a retry loop with the same key changes nothing. An
//     expired credential, or one an agent CA rotation orphaned, is renewed
//     by steps 5-6;
//  5. at most MaxEnrolledCredentialsPerHost - 1 active credentials of other
//     identities may exist on the host;
//  6. sign (only now), delete the identity's previous credential (renewal),
//     insert the new one, and audit both, failing the whole transaction when
//     an audit row cannot be written.
//
// The replay runs after steps 1-3 (a revoked host, a rotated key, a closed
// window or a name now taken by another agent gets no certificate, not even
// one it already holds) and before step 5: the cap bounds new credentials,
// and a replay adds none.
func (r *HostEnrollRepo) IssueHostCredential(ctx context.Context, in domain.HostEnrollIssue) (*domain.HostEnrollResult, error) {
	if in.Sign == nil {
		return nil, errors.New("host enroll: no signer")
	}
	if in.KeyLookup == "" {
		return nil, domain.ErrHostKeyInvalid
	}
	res := &domain.HostEnrollResult{}
	err := inTx(ctx, r.pool, func(tx pgx.Tx) error {
		var revoked, open, current bool
		var window *time.Time
		err := tx.QueryRow(ctx, `
			SELECT name, revoked_at IS NOT NULL, enroll_expires_at, COALESCE(enroll_expires_at > NOW(), false),
			       COALESCE(host_key_lookup = $3, false)
			  FROM hosts
			 WHERE id = $1 AND project_id = $2
			   FOR UPDATE`,
			in.HostID, in.ProjectID, in.KeyLookup).Scan(&res.HostName, &revoked, &window, &open, &current)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrEnrollHostRevoked
		}
		if err != nil {
			return err
		}
		if revoked {
			return domain.ErrEnrollHostRevoked
		}
		if !current {
			// Rotated between the key check and this lock: the verified key
			// is now the previous key, which never enrolls.
			return domain.ErrHostKeyInvalid
		}
		if !open || window == nil {
			return domain.ErrEnrollWindowClosed
		}
		res.EnrollExpiresAt = *window

		// The name may be used by nothing but this identity on this host:
		// not by an agent row of another host, of no host (adopting an
		// unattached row would hand a host key another machine's agent and
		// bundle), or of the other kind (agents are later looked up by name
		// alone), nor by an enrolled credential of another host or kind.
		var taken bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM agents
			                WHERE project_id = $1 AND deleted_at IS NULL AND name = $2
			                  AND NOT (host_id IS NOT NULL AND host_id = $3
			                           AND `+enrollAgentKindSQL+` = $4))
			    OR EXISTS (SELECT 1 FROM mtls_credentials
			                WHERE project_id = $1 AND agent_name = $2 AND host_id IS NOT NULL
			                  AND NOT (host_id = $3 AND agent_kind = $4))`,
			in.ProjectID, in.AgentName, in.HostID, in.AgentKind).Scan(&taken); err != nil {
			return err
		}
		if taken {
			return domain.ErrEnrollAgentNameTaken
		}

		// One enrollment per identity per window: a credential of this
		// identity issued since the window opened is answered only for a
		// request with the same public key (the installer retrying with the
		// key it holds). Otherwise a leaked host key could take the identity
		// over from the host that enrolled it.
		var usedInWindow bool
		var existing struct {
			id, certPEM, fingerprint string
			notAfter                 *time.Time
		}
		err = tx.QueryRow(ctx, `
			SELECT created_at > $5::timestamptz - make_interval(secs => $6), id, client_cert_pem,
			       cert_fingerprint_sha256, not_after
			  FROM mtls_credentials
			 WHERE project_id = $1 AND host_id = $2 AND agent_kind = $3 AND agent_name = $4
			 ORDER BY created_at DESC LIMIT 1`,
			in.ProjectID, in.HostID, in.AgentKind, in.AgentName, *window, domain.HostEnrollWindow.Seconds(),
		).Scan(&usedInWindow, &existing.id, &existing.certPEM, &existing.fingerprint, &existing.notAfter)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && usedInWindow {
			if !samePublicKey(existing.certPEM, in.PublicKeyDER) {
				return domain.ErrEnrollUsed
			}
			// Same key: hand back the credential the requester already
			// holds while it is usable. Nothing is written, so repeating
			// the request costs no signature, no audit row and no dropped
			// agent stream.
			now := time.Now()
			if existing.notAfter != nil && existing.notAfter.After(now) && existing.fingerprint != "" &&
				chainsToCA(existing.certPEM, in.CACertPEM, now) {
				res.Replayed = true
				res.CredentialID, res.CertPEM = existing.id, existing.certPEM
				res.Fingerprint, res.NotAfter = existing.fingerprint, *existing.notAfter
				return nil
			}
		}

		var others int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM mtls_credentials
			 WHERE project_id = $1 AND host_id = $2
			   AND (not_after IS NULL OR not_after > NOW())
			   AND NOT (agent_kind = $3 AND agent_name = $4)`,
			in.ProjectID, in.HostID, in.AgentKind, in.AgentName).Scan(&others); err != nil {
			return err
		}
		if others >= domain.MaxEnrolledCredentialsPerHost {
			return domain.ErrEnrollLimit
		}

		certPEM, notAfter, err := in.Sign()
		if err != nil {
			return err
		}
		fp := FingerprintFromPEM([]byte(certPEM))
		if fp == "" {
			return errors.New("host enroll: signed certificate does not parse")
		}

		rows, err := tx.Query(ctx, `
			DELETE FROM mtls_credentials
			 WHERE project_id = $1 AND host_id = $2 AND agent_kind = $3 AND agent_name = $4
			RETURNING `+credentialColumns,
			in.ProjectID, in.HostID, in.AgentKind, in.AgentName)
		if err != nil {
			return err
		}
		old, err := scanCredentials(rows)
		if err != nil {
			return err
		}

		var createdAt time.Time
		if err := tx.QueryRow(ctx, `
			INSERT INTO mtls_credentials
			       (project_id, name, client_cert_pem, cert_fingerprint_sha256, purpose,
			        host_id, agent_kind, agent_name, not_after)
			VALUES ($1, $2, $3, $4, 'agent_grpc', $5, $6, $7, $8)
			RETURNING id, created_at`,
			in.ProjectID, in.AgentName, certPEM, fp, in.HostID, in.AgentKind, in.AgentName, notAfter,
		).Scan(&res.CredentialID, &createdAt); err != nil {
			return err
		}
		res.Fingerprint, res.CertPEM, res.NotAfter = fp, certPEM, notAfter

		for _, c := range old {
			res.Superseded = append(res.Superseded, c.ID)
			if err := auditInTx(ctx, tx, AuditEvent{
				ProjectID: in.ProjectID, Action: AuditCredentialRevoked,
				TargetType: "credential", TargetID: c.ID, TargetName: c.Name,
				IP: in.SourceIP, UserAgent: in.UserAgent,
				MetadataJSON: map[string]any{
					"via": "host_enroll_renewal", "credential_id": c.ID, "fingerprint": c.CertFingerprintSHA256,
					"host_id": in.HostID, "agent_kind": c.AgentKind, "agent_name": c.AgentName,
					"replaced_by": res.CredentialID,
				},
			}); err != nil {
				return err
			}
		}
		return auditInTx(ctx, tx, AuditEvent{
			ProjectID: in.ProjectID, Action: AuditCredentialProvisioned,
			TargetType: "credential", TargetID: res.CredentialID, TargetName: in.AgentName,
			IP: in.SourceIP, UserAgent: in.UserAgent,
			MetadataJSON: map[string]any{
				"via": "host_enroll", "host_id": in.HostID, "host_name": res.HostName,
				"agent_kind": in.AgentKind, "agent_name": in.AgentName,
				"fingerprint": fp, "valid_until": notAfter.UTC().Format(time.RFC3339),
				"renewal": len(old) > 0,
			},
		})
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "uq_mtls_credentials_agent" {
			// The same identity enrolled on another host at the same moment.
			return nil, domain.ErrEnrollAgentNameTaken
		}
		return nil, err
	}
	return res, nil
}

// samePublicKey reports whether certPEM carries the public key spkiDER.
func samePublicKey(certPEM string, spkiDER []byte) bool {
	if len(spkiDER) == 0 {
		return false
	}
	cert := parseCertPEM(certPEM)
	if cert == nil {
		return false
	}
	return subtle.ConstantTimeCompare(cert.RawSubjectPublicKeyInfo, spkiDER) == 1
}

// chainsToCA reports whether certPEM is a client certificate signed by
// caPEM and valid at now (the checks the agent gRPC listener makes).
func chainsToCA(certPEM, caPEM string, now time.Time) bool {
	cert := parseCertPEM(certPEM)
	ca := parseCertPEM(caPEM)
	if cert == nil || ca == nil {
		return false
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err == nil
}

// parseCertPEM parses the first PEM block of s as a certificate, nil when
// it is not one.
func parseCertPEM(s string) *x509.Certificate {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return cert
}

// RecordEnrollRefusal: see domain.HostEnrollStore. No actor: the caller
// authenticated with a host key, not as a user.
func (r *HostEnrollRepo) RecordEnrollRefusal(ctx context.Context, ref domain.HostEnrollRefusal) error {
	ev := AuditEvent{
		ProjectID: ref.ProjectID, Action: AuditHostEnrollRefused,
		TargetType: "host", TargetID: ref.HostID, TargetName: ref.HostName,
		IP: ref.SourceIP, UserAgent: ref.UserAgent,
		MetadataJSON: map[string]any{
			"via": "host_enroll", "code": ref.Code, "host_id": ref.HostID,
			"agent_kind": ref.AgentKind, "agent_name": ref.AgentName,
		},
	}
	return noteAuditFailure("agent_audit", ev.Action, insertAudit(ctx, r.pool, ev))
}
