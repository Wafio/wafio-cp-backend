package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/certutil"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/keyauth"
)

// Host-key enrollment:
// POST /api/internal/host-enroll. The host's installer sends a CSR and its
// host key; the control plane checks both and issues a client certificate
// bound to that host and one agent. The private key never leaves the host.

var (
	// ErrEnrollAgentKind: agent_kind is neither "host" nor "waf".
	ErrEnrollAgentKind = errors.New("agent_kind must be host or waf")
	// ErrEnrollAgentName: agent_name is empty, too long or has characters
	// outside [A-Za-z0-9._@:-].
	ErrEnrollAgentName = errors.New("agent_name must be 1-128 characters of letters, digits and . _ @ : -, starting with a letter or digit")
	// ErrEnrollKeyCheckUnavailable: the host key could not be checked (database
	// error, no verification slot before the deadline); says nothing about the
	// key, the installer retries.
	ErrEnrollKeyCheckUnavailable = errors.New("host key check unavailable; retry")
)

// CredentialDisconnector closes the open agent streams of a credential
// (agentserver.Server).
type CredentialDisconnector interface {
	DisconnectCredential(credID string) int
}

// HostEnrollment issues host-bound client certificates.
type HostEnrollment struct {
	Store domain.HostEnrollStore
	// Streams closes the streams of a credential a renewal replaced (nil:
	// they end at their next credential re-check).
	Streams CredentialDisconnector
	// GRPCEndpoint is "<server.grpc_domain>:<port>", "" when grpc_domain is
	// unset; GRPCServerName the name in the gRPC server certificate
	// (grpc_domain, or localhost).
	GRPCEndpoint   string
	GRPCServerName string
	// CertValidity overrides domain.EnrolledCertValidity (tests).
	CertValidity time.Duration
}

// HostEnrollRequest is one enrollment as the handler read it.
type HostEnrollRequest struct {
	HostKey   string
	CSRPEM    string
	AgentKind string
	AgentName string
	SourceIP  string
	UserAgent string
}

// HostEnrollResponse is the 201 body.
type HostEnrollResponse struct {
	CredentialID    string  `json:"credential_id"`
	HostID          string  `json:"host_id"`
	HostName        string  `json:"host_name"`
	AgentKind       string  `json:"agent_kind"`
	AgentName       string  `json:"agent_name"`
	ClientCert      string  `json:"client_cert"`
	CACert          string  `json:"ca_cert"`
	CASHA256        string  `json:"ca_sha256"`
	Fingerprint     string  `json:"fingerprint"`
	ValidUntil      string  `json:"valid_until"`
	GRPCEndpoint    *string `json:"grpc_endpoint"`
	GRPCServerName  string  `json:"grpc_server_name"`
	Renewed         bool    `json:"renewed"`
	Replayed        bool    `json:"replayed"`
	EnrollExpiresAt string  `json:"enroll_expires_at"`
}

// NormalizeEnrollKind maps the requested kind: "" and "host" (and the
// legacy "ebpf") are a host agent, "waf" a WAF agent.
func NormalizeEnrollKind(kind string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "", domain.AgentKindHost, "ebpf":
		return domain.AgentKindHost, nil
	case domain.AgentKindWAF:
		return domain.AgentKindWAF, nil
	}
	return "", ErrEnrollAgentKind
}

// Enroll checks the request (cheap checks first: kind, name, CSR; then the
// host key, argon2id), then lets the store check the window, the name and
// the per-host cap and issue the certificate. Errors: ErrEnrollAgentKind,
// ErrEnrollAgentName, certutil.ErrInvalidCSR (wrapped), domain.ErrHostKeyInvalid,
// ErrEnrollKeyCheckUnavailable, domain.ErrEnrollHostRevoked,
// domain.ErrEnrollWindowClosed, domain.ErrEnrollLimit,
// domain.ErrEnrollAgentNameTaken, domain.ErrEnrollUsed,
// domain.ErrEnrollUnavailable, or an internal error.
func (s *HostEnrollment) Enroll(ctx context.Context, req HostEnrollRequest) (*HostEnrollResponse, error) {
	kind, err := NormalizeEnrollKind(req.AgentKind)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.AgentName)
	if !domain.ValidEnrollAgentName(name) {
		return nil, ErrEnrollAgentName
	}
	csr, err := certutil.ParseEnrollCSR([]byte(req.CSRPEM))
	if err != nil {
		return nil, err
	}

	host, err := s.Store.VerifyCurrentHostKey(ctx, strings.TrimSpace(req.HostKey))
	if errors.Is(err, domain.ErrHostKeyInvalid) {
		return nil, domain.ErrHostKeyInvalid
	}
	if err != nil {
		slog.Warn("host_enroll_key_check_failed", "ip", req.SourceIP, "err", err)
		return nil, ErrEnrollKeyCheckUnavailable
	}

	caCertPEM, caKeyPEM, err := s.Store.AgentCA(ctx)
	if err != nil {
		return nil, err
	}
	caSHA, err := pemSHA256(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("agent CA: %w", err)
	}
	validity := s.CertValidity
	if validity <= 0 {
		validity = domain.EnrolledCertValidity
	}

	res, err := s.Store.IssueHostCredential(ctx, domain.HostEnrollIssue{
		ProjectID: host.ProjectID, HostID: host.ID, AgentKind: kind, AgentName: name,
		KeyLookup:    keyauth.LookupID(strings.TrimSpace(req.HostKey)),
		PublicKeyDER: csr.RawSubjectPublicKeyInfo,
		CACertPEM:    caCertPEM,
		SourceIP:     req.SourceIP, UserAgent: req.UserAgent,
		Sign: func() (string, time.Time, error) {
			certPEM, notAfter, serr := certutil.SignHostClientCert([]byte(caCertPEM), []byte(caKeyPEM), csr,
				certutil.HostClientCertOptions{HostID: host.ID, AgentKind: kind, AgentName: name, Validity: validity})
			return string(certPEM), notAfter, serr
		},
	})
	if err != nil {
		if code := refusalCode(err); code != "" {
			// A key that verified but cannot enroll: audited (a valid key
			// outside its window is a leak signal). Best effort.
			if aerr := s.Store.RecordEnrollRefusal(ctx, domain.HostEnrollRefusal{
				ProjectID: host.ProjectID, HostID: host.ID, HostName: host.Name, Code: code,
				AgentKind: kind, AgentName: name, SourceIP: req.SourceIP, UserAgent: req.UserAgent,
			}); aerr != nil {
				slog.Error("host_enroll_refusal_audit_failed", "host_id", host.ID, "code", code, "err", aerr)
			}
		}
		return nil, err
	}

	if res.Replayed {
		// The stored credential, unchanged (same-key retry): the store wrote
		// nothing, so there is nothing to disconnect; Debug only, a retry
		// loop must not flood the log.
		slog.Debug("host_enroll_replayed", "project_id", host.ProjectID, "host_id", host.ID, "agent_kind", kind,
			"agent_name", name, "credential_id", res.CredentialID, "ip", req.SourceIP)
	} else {
		for _, id := range res.Superseded {
			if s.Streams != nil {
				s.Streams.DisconnectCredential(id)
			}
		}
		slog.Info("host_enrolled", "project_id", host.ProjectID, "host_id", host.ID, "agent_kind", kind,
			"agent_name", name, "credential_id", res.CredentialID, "fingerprint", res.Fingerprint,
			"renewed", len(res.Superseded) > 0, "ip", req.SourceIP)
	}

	out := &HostEnrollResponse{
		CredentialID: res.CredentialID, HostID: host.ID, HostName: res.HostName,
		AgentKind: kind, AgentName: name,
		ClientCert: res.CertPEM, CACert: caCertPEM, CASHA256: caSHA,
		Fingerprint: res.Fingerprint, ValidUntil: res.NotAfter.UTC().Format(time.RFC3339),
		GRPCServerName: s.GRPCServerName, Renewed: len(res.Superseded) > 0, Replayed: res.Replayed,
		EnrollExpiresAt: res.EnrollExpiresAt.UTC().Format(time.RFC3339),
	}
	if s.GRPCEndpoint != "" {
		ep := s.GRPCEndpoint
		out.GRPCEndpoint = &ep
	}
	if out.GRPCServerName == "" {
		out.GRPCServerName = "localhost"
	}
	return out, nil
}

// refusalCode is the audited code of a refusal after the key verified, ""
// for errors that are not one.
func refusalCode(err error) string {
	switch {
	case errors.Is(err, domain.ErrEnrollWindowClosed):
		return "ENROLL_EXPIRED"
	case errors.Is(err, domain.ErrEnrollLimit):
		return "ENROLL_LIMIT"
	case errors.Is(err, domain.ErrEnrollAgentNameTaken):
		return "AGENT_NAME_TAKEN"
	case errors.Is(err, domain.ErrEnrollUsed):
		return "ENROLL_USED"
	case errors.Is(err, domain.ErrEnrollHostRevoked):
		return "AGENT_REVOKED"
	}
	return ""
}

// pemSHA256 is the lowercase hex SHA-256 of the first PEM block's DER (the
// CA fingerprint GET /agent-connect-info reports and the installer pins).
func pemSHA256(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", errors.New("certificate is not PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}
