package handlers

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/certutil"
)

// AgentCredentialHandler exposes the project-scoped REST endpoints used by the
// dashboard to mint and manage WAF agent gRPC credentials. The actual
// gRPC stream lives in internal/agentserver.
type AgentCredentialHandler struct {
	Repo *repository.Repository
	// CertWarnBeforeDays: a credential is flagged "expiring" when its cert
	// expires within this many days. 0 → 30.
	CertWarnBeforeDays int
	// Streams ends the open agent streams of a revoked credential
	// (agentserver.Server in production; nil disables it).
	Streams CredentialStreams
	// GRPCDomain is server.grpc_domain (the gRPC server certificate's
	// name); GRPCPort the port of server.agent_grpc_addr (0 = 9090).
	GRPCDomain          string
	GRPCPort            uint16
	ControlPlaneVersion string
	// CACerts reads the CA certificate for GET /agent-connect-info; nil =
	// Repo.AgentGRPC.
	CACerts caCertReader
}

// CredentialStreams is the part of the agent gRPC server the revoke endpoint
// needs.
type CredentialStreams interface {
	DisconnectCredential(credID string) int
}

// errCredentialNotFound answers a revoke of an id that is not a credential
// of the caller's project; another project's id gets the same answer.
var errCredentialNotFound = newPublicError(fiber.StatusNotFound, "CREDENTIAL_NOT_FOUND", "Credential not found.")

// CA validity = 10 years (rotating CA == every agent reprovisions, so we
// pick a generous default and let the operator rotate manually if needed).
const agentGRPCCAValidity = 10 * 365 * 24 * time.Hour

// ensureCA loads the global agent gRPC CA, generating it the first time.
// Caller holds no lock; concurrent first-time calls are safe because the
// unique partial index (project_id IS NULL) on agent_grpc_ca rejects
// duplicates and we fall back to GetGlobalCA on insert error.
func (h *AgentCredentialHandler) ensureCA(ctx context.Context) (*repository.AgentGRPCCA, error) {
	ca, err := h.Repo.AgentGRPC.GetGlobalCA(ctx)
	if err == nil {
		return ca, nil
	}
	certPEM, keyPEM, gerr := certutil.GenerateCA(agentGRPCCAValidity)
	if gerr != nil {
		return nil, gerr
	}
	notAfter := time.Now().Add(agentGRPCCAValidity)
	created, ierr := h.Repo.AgentGRPC.CreateGlobalCA(ctx, string(certPEM), string(keyPEM), notAfter)
	if ierr == nil {
		return created, nil
	}
	// Probably a race — re-read.
	if existing, rerr := h.Repo.AgentGRPC.GetGlobalCA(ctx); rerr == nil {
		return existing, nil
	}
	return nil, ierr
}

type agentGRPCProvisionReq struct {
	Name         string `json:"name"`
	ValidityDays int    `json:"validity_days"` // 0 = default 365
}

type agentGRPCProvisionResp struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	CACert      string `json:"ca_cert"`
	ClientCert  string `json:"client_cert"`
	ClientKey   string `json:"client_key"`
	Fingerprint string `json:"fingerprint"`
	ServerHint  string `json:"server_hint,omitempty"` // suggested --server gRPC address
	CreatedAt   string `json:"created_at"`
	ValidUntil  string `json:"valid_until"`
}

// Provision mints a new client cert for one WAF agent and returns the
// full bundle (CA + client cert + client key). The private key is never
// stored server-side.
//
// POST /api/projects/:id/agent-grpc-credentials
func (h *AgentCredentialHandler) Provision(c *fiber.Ctx) error {
	projectID := c.Params("id")
	if projectID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing project id"})
	}

	var body agentGRPCProvisionReq
	_ = c.BodyParser(&body)
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = "wafio-waf-agent"
	}

	validityDays := body.ValidityDays
	if validityDays <= 0 {
		validityDays = 365
	}
	if validityDays > 36500 {
		validityDays = 36500
	}
	clientValidity := time.Duration(validityDays) * 24 * time.Hour

	ca, err := h.ensureCA(c.UserContext())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to load CA",
		})
	}

	clientCertPEM, clientKeyPEM, cerr := certutil.GenerateClientCert(
		[]byte(ca.CertPEM), []byte(ca.KeyPEM), clientValidity,
	)
	if cerr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to sign client cert",
		})
	}

	// The credential and its audit row commit together: a client
	// certificate is never trusted without an audit entry.
	userID, _ := c.Locals("user_id").(string)
	cred, ierr := h.Repo.AgentGRPC.CreateAgentCredentialAudited(
		c.UserContext(), projectID, name, string(clientCertPEM),
		func(cred *repository.MTLSCredential) repository.AuditEvent {
			return repository.AuditEvent{
				ProjectID: projectID, ActorUserID: userID,
				Action: repository.AuditCredentialProvisioned, TargetType: "credential", TargetID: cred.ID, TargetName: cred.Name,
				IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
				MetadataJSON: map[string]any{"name": name, "validity_days": validityDays, "fingerprint": cred.CertFingerprintSHA256},
			}
		},
	)
	if ierr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to persist credential",
		})
	}
	return c.Status(fiber.StatusCreated).JSON(agentGRPCProvisionResp{
		ID:          cred.ID,
		Name:        cred.Name,
		CACert:      ca.CertPEM,
		ClientCert:  string(clientCertPEM),
		ClientKey:   string(clientKeyPEM),
		Fingerprint: cred.CertFingerprintSHA256,
		ServerHint:  h.grpcEndpoint(),
		CreatedAt:   cred.CreatedAt.Format(time.RFC3339),
		ValidUntil:  time.Now().Add(clientValidity).Format(time.RFC3339),
	})
}

// List returns provisioned agent credentials (without keys, since keys are
// never stored server-side anyway), paged with ?limit= (≤ 100; omitted = up
// to 100) and ?offset=.
//
// GET /api/projects/:id/agent-grpc-credentials?limit=&offset=
func (h *AgentCredentialHandler) List(c *fiber.Ctx) error {
	projectID := c.Params("id")
	if projectID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing project id", "code": "BAD_REQUEST"})
	}
	all, err := h.Repo.AgentGRPC.ListAgentCredentials(c.UserContext(), projectID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error", "code": "INTERNAL_ERROR"})
	}
	page := parsePage(c, maxListLimit)
	rows := pageOf(all, page)
	out := make([]fiber.Map, 0, len(rows))
	for _, r := range rows {
		entry := fiber.Map{
			"id":          r.ID,
			"name":        r.Name,
			"fingerprint": r.CertFingerprintSHA256,
			"created_at":  r.CreatedAt.Format(time.RFC3339),
		}
		if r.HostBound() {
			// Enrolled with a host key: bound to one agent on one host and
			// revoked with that host.
			entry["host_id"] = r.HostID
			entry["host_name"] = r.HostName
			entry["agent_kind"] = r.AgentKind
			entry["agent_name"] = r.AgentName
		}
		if na, perr := certutil.ParseNotAfter([]byte(r.ClientCertPEM)); perr == nil {
			entry["valid_until"] = na.Format(time.RFC3339)
			now := time.Now()
			warnDays := h.CertWarnBeforeDays
			if warnDays <= 0 {
				warnDays = 30
			}
			entry["expired"] = !na.After(now)
			entry["expiring"] = na.After(now) && na.Before(now.Add(time.Duration(warnDays)*24*time.Hour))
		}
		out = append(out, entry)
	}
	return c.JSON(fiber.Map{"credentials": out, "total": len(all), "limit": page.Limit, "offset": page.Offset})
}

// Revoke deletes a credential and ends every open agent stream that
// authenticated with it. An id that is not a credential of this
// project, including another project's, is 404 and writes no audit entry.
//
// DELETE /api/projects/:id/agent-grpc-credentials/:credId
func (h *AgentCredentialHandler) Revoke(c *fiber.Ctx) error {
	projectID := c.Params("id")
	credID := c.Params("credId")
	if projectID == "" || credID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing param"})
	}
	// Canonical form: the stream registry is keyed by the id as stored
	// (lowercase, hyphenated), and Postgres accepts other spellings, so an
	// uppercase id would delete the row but close no stream. uuid.Parse also
	// accepts urn:uuid: and braces, which Postgres rejects.
	parsed, err := uuid.Parse(credID)
	if err != nil {
		return errCredentialNotFound
	}
	credID = parsed.String()
	// Delete and audit commit together. Streams are closed after the
	// commit, so a reconnect can no longer authenticate with the credential;
	// the number closed is therefore logged, not part of the audit row.
	revokeUserID, _ := c.Locals("user_id").(string)
	deleted, err := h.Repo.AgentGRPC.DeleteAgentCredentialAudited(c.UserContext(), credID, projectID, repository.AuditEvent{
		ProjectID: projectID, ActorUserID: revokeUserID,
		Action: repository.AuditCredentialRevoked, TargetType: "credential", TargetID: credID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"credential_id": credID},
	})
	if err != nil {
		slog.Error("credential_revoke_failed", "project_id", projectID, "credential_id", credID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	if !deleted {
		return errCredentialNotFound
	}
	if h.Streams != nil {
		closed := h.Streams.DisconnectCredential(credID)
		slog.Info("credential_revoked", "project_id", projectID, "credential_id", credID, "streams_closed", closed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}
