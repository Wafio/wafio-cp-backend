package handlers

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/validate"
)

// HostsHandler serves the customer-facing (JWT-authenticated) Host CRUD
// endpoints under `/api/projects/:id/hosts`.
type HostsHandler struct {
	Repo *repository.Repository
	// FleetSvc serves GET /hosts/fleet (the method of that name is the
	// handler).
	FleetSvc *application.HostFleet
	// Streams ends the agent streams of a revoked or deleted host
	// (agentserver.Server in production; nil disables it).
	Streams HostStreams
}

// HostStreams is the part of the agent gRPC server host revoke and delete
// need: revoking a host used to only mark the row while its agents
// stayed connected and kept receiving desired firewall state. The
// credentials enrolled for the host are revoked with it, so their
// streams are closed by credential as well.
type HostStreams interface {
	DisconnectHost(projectID, hostID string, agentIDs []string) int
	DisconnectCredential(credID string) int
}

// hostCredentialAudit builds the credential.revoked row of an enrolled
// credential removed by a host revoke or delete (via = host_revoke |
// host_delete).
func hostCredentialAudit(c *fiber.Ctx, host *repository.Host, via string) repository.HostCredentialAudit {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	ip, ua := c.IP(), string(c.Request().Header.UserAgent())
	return func(cred repository.MTLSCredential) repository.AuditEvent {
		return repository.AuditEvent{
			ProjectID: host.ProjectID, ActorUserID: userID,
			Action: repository.AuditCredentialRevoked, TargetType: "credential",
			TargetID: cred.ID, TargetName: cred.Name,
			IP: ip, UserAgent: ua,
			MetadataJSON: map[string]any{
				"via": via, "credential_id": cred.ID, "fingerprint": cred.CertFingerprintSHA256,
				"host_id": host.ID, "host_name": host.Name,
				"agent_kind": cred.AgentKind, "agent_name": cred.AgentName,
			},
		}
	}
}

// disconnectCredentials closes the streams of the removed credentials.
func (h *HostsHandler) disconnectCredentials(creds []repository.MTLSCredential) {
	if h.Streams == nil {
		return
	}
	for _, cred := range creds {
		h.Streams.DisconnectCredential(cred.ID)
	}
}

// disconnectHost ends the open agent streams of host (best effort; Hello
// refuses the reconnect of a revoked host's agents either way).
func (h *HostsHandler) disconnectHost(host *repository.Host, agentIDs []string) {
	if h.Streams == nil {
		return
	}
	h.Streams.DisconnectHost(host.ProjectID, host.ID, agentIDs)
}

// hostAgentIDs lists the ids of host's agents (nil on error; the stream
// match by host id still applies).
func (h *HostsHandler) hostAgentIDs(c *fiber.Ctx, host *repository.Host) []string {
	agents, err := h.Repo.EBPF.ListAgentsByHost(c.UserContext(), host.ID)
	if err != nil {
		slog.Warn("host_agents_lookup_failed", "host_id", host.ID, "err", err)
		return nil
	}
	ids := make([]string, 0, len(agents))
	for _, a := range agents {
		ids = append(ids, a.ID)
	}
	return ids
}

type createHostBody struct {
	Name   string            `json:"name"   validate:"required,min=2,max=64"`
	Labels map[string]string `json:"labels" validate:"omitempty"`
}

// Create generates a new host + its one-shot Host Key. The raw key is
// returned in the response body and MUST be displayed to the user only once.
// Subsequent reads only reveal the short prefix.
func (h *HostsHandler) Create(c *fiber.Ctx) error {
	userID := c.Locals(auth.UserIDKey).(string)
	projectID := c.Params("id")

	var body createHostBody
	err := c.BodyParser(&body)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	err = validate.Struct(&body)
	if err != nil {
		return validationFailed(c, err)
	}
	if !validate.PlainText(body.Name) {
		return rejectUnsafeName(c, "name")
	}
	labels, code, err := validateHostLabels(body.Labels)
	if err != nil {
		return invalidInput(c, code, err)
	}
	body.Labels = labels
	if _, err = h.Repo.Project.GetByID(c.UserContext(), projectID); err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
	}

	host, raw, err := h.Repo.Host.Create(c.UserContext(), userID, projectID, body.Name, body.Labels)
	if err != nil {
		if errors.Is(err, repository.ErrHostLimit) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": fmt.Sprintf("host limit reached: at most %d hosts per project", repository.MaxHostsPerProject),
				"code":  "HOST_LIMIT_REACHED",
			})
		}
		if isUniqueViolation(err) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": "A host with this name already exists in this project.",
				"code":  "CONFLICT",
			})
		}
		apiErr := ResolveDBError(err, "host")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}

	// Seed built-in detection rules for this host (best-effort). A failure is
	// repaired by the startup seeder or by the first rule write for the host.
	if err := h.Repo.DetectionRules.SeedBuiltinRules(c.UserContext(), projectID, host.ID); err != nil {
		slog.Warn("host_builtin_rules_seed_failed", "project_id", projectID, "host_id", host.ID, "err", err)
	}

	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: userID,
		Action: repository.AuditHostCreated, TargetType: "host",
		TargetID: host.ID, TargetName: host.Name,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"name": host.Name, "labels": body.Labels, "prefix": host.HostKeyPrefix},
	})

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"host":              host,
		"host_key":          raw,
		"enroll_expires_at": host.EnrollExpiresAt,
		"warning":           "Copy now — the full host key is never shown again.",
	})
}

// List returns the hosts of the current project (revoked hosts included, so
// operators can tell that a key was withdrawn), paged with ?limit= (≤ 100;
// omitted = up to 100) and ?offset=.
//
//	GET /api/projects/:id/hosts?limit=&offset=
func (h *HostsHandler) List(c *fiber.Ctx) error {
	projectID := c.Params("id")
	_, err := h.Repo.Project.GetByID(c.UserContext(), projectID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found", "code": "PROJECT_NOT_FOUND"})
	}
	rows, err := h.Repo.Host.ListByProject(c.UserContext(), projectID)
	if err != nil {
		apiErr := ResolveDBError(err, "host")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	if rows == nil {
		rows = []repository.Host{}
	}
	page := parsePage(c, maxListLimit)
	return c.JSON(fiber.Map{"hosts": pageOf(rows, page), "total": len(rows), "limit": page.Limit, "offset": page.Offset})
}

// Fleet returns one page of the project's hosts with a protection summary
// each (firewall, runtime, incidents, agents, attention). ?limit= (≤ 100,
// default 100), ?offset=, optional ?host_id= for one host (an unknown id is
// an empty page). Filters are client-side.
//
//	GET /api/projects/:id/hosts/fleet?limit=&offset=&host_id=
func (h *HostsHandler) Fleet(c *fiber.Ctx) error {
	projectID := c.Params("id")
	hostID := strings.TrimSpace(c.Query("host_id"))
	if hostID != "" {
		if _, err := uuid.Parse(hostID); err != nil || len(hostID) != 36 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "host_id must be a host id", "code": "BAD_REQUEST"})
		}
	}
	page := parsePage(c, maxListLimit)
	out, err := h.FleetSvc.Page(c.UserContext(), projectID, hostID, page.Limit, page.Offset)
	if err != nil {
		slog.Error("host_fleet_failed", "project_id", projectID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error", "code": "INTERNAL_ERROR"})
	}
	return c.JSON(out)
}

// Get returns a single host with its current host_info snapshot.
func (h *HostsHandler) Get(c *fiber.Ctx) error {
	host, err := h.owner(c)
	if err != nil {
		return nil
	}
	return c.JSON(fiber.Map{"host": host})
}

// RotateKey mints a fresh key. The previous key keeps binding agents at
// Hello for repository.HostKeyGracePeriod but never enrolls; the new key
// opens a domain.HostEnrollWindow enrollment window (renewal of enrolled
// certificates = rotate, then run the install command again).
func (h *HostsHandler) RotateKey(c *fiber.Ctx) error {
	host, err := h.owner(c)
	if err != nil {
		return nil
	}
	raw, enrollUntil, err := h.Repo.Host.RotateKey(c.UserContext(), host.ProjectID, host.ID)
	if errors.Is(err, repository.ErrHostNotRotatable) {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "a revoked host's key cannot be rotated", "code": "HOST_REVOKED"})
	}
	if err != nil {
		apiErr := ResolveDBError(err, "host")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	userID, _ := c.Locals(auth.UserIDKey).(string)
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: host.ProjectID, ActorUserID: userID,
		Action: repository.AuditHostKeyRotated, TargetType: "host",
		TargetID: host.ID, TargetName: host.Name,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"host_name": host.Name, "host_id": host.ID},
	})
	return c.JSON(fiber.Map{
		"host_key":          raw,
		"enroll_expires_at": enrollUntil,
		"warning":           "Copy now — the full host key is never shown again.",
	})
}

// Revoke marks the host as revoked (keeping the row for audit). Its host key
// stops verifying, its agents' open gRPC streams are closed and their
// reconnects are refused at Hello. Every mTLS credential enrolled
// for the host is revoked in the same transaction (one credential.revoked
// row each) and its streams closed, so the machine cannot reconnect under
// another agent name either. Project-wide credentials (made on the
// Credentials page, bound to no host) are not touched.
func (h *HostsHandler) Revoke(c *fiber.Ctx) error {
	host, err := h.owner(c)
	if err != nil {
		return nil
	}
	creds, err := h.Repo.Host.RevokeWithCredentials(c.UserContext(), host.ProjectID, host.ID, hostCredentialAudit(c, host, "host_revoke"))
	if err != nil {
		apiErr := ResolveDBError(err, "host")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	h.disconnectCredentials(creds)
	h.disconnectHost(host, h.hostAgentIDs(c, host))
	userID, _ := c.Locals(auth.UserIDKey).(string)
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: host.ProjectID, ActorUserID: userID,
		Action: repository.AuditHostRevoked, TargetType: "host",
		TargetID: host.ID, TargetName: host.Name,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"host_name": host.Name, "credentials_revoked": len(creds)},
	})
	return c.JSON(fiber.Map{"revoked": true, "credentials_revoked": len(creds)})
}

// Delete removes the host and cascades the removal to all attached agents.
// Agents registered via gRPC mTLS (host_id IS NULL) are deleted explicitly
// by matching their hostname column against the host's name. The host's
// enrolled credentials are revoked (audited) before the row goes, and their
// streams closed.
func (h *HostsHandler) Delete(c *fiber.Ctx) error {
	host, err := h.owner(c)
	if err != nil {
		return nil
	}
	// The cascade below removes the linked agents; their ids are read first
	// so their open streams can be closed too.
	agentIDs := h.hostAgentIDs(c, host)
	// Delete unlinked (mTLS) agents whose hostname matches the host name before
	// removing the host row so that ON DELETE CASCADE handles the linked ones.
	_ = h.Repo.EBPF.DeleteUnattachedAgentsByHostname(c.UserContext(), host.ProjectID, host.Name)

	creds, err := h.Repo.Host.DeleteWithCredentials(c.UserContext(), host.ProjectID, host.ID, hostCredentialAudit(c, host, "host_delete"))
	if err != nil {
		apiErr := ResolveDBError(err, "host")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	h.disconnectCredentials(creds)
	h.disconnectHost(host, agentIDs)
	userID, _ := c.Locals(auth.UserIDKey).(string)
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: host.ProjectID, ActorUserID: userID,
		Action: repository.AuditHostDeleted, TargetType: "host",
		TargetID: host.ID, TargetName: host.Name,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"host_name": host.Name, "credentials_revoked": len(creds)},
	})
	return c.JSON(fiber.Map{"deleted": true, "credentials_revoked": len(creds)})
}

// ListAgents returns every agent that has registered under this host
// (both kinds, ebpf + waf).
func (h *HostsHandler) ListAgents(c *fiber.Ctx) error {
	host, err := h.owner(c)
	if err != nil {
		return nil
	}
	agents, qErr := h.Repo.EBPF.ListAgentsByHost(c.UserContext(), host.ID)
	if qErr != nil {
		apiErr := ResolveDBError(qErr, "agent")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	if agents == nil {
		agents = []repository.AgentWithHostInfo{}
	}
	page := parsePage(c, maxListLimit)
	return c.JSON(fiber.Map{"agents": pageOf(agents, page), "total": len(agents), "limit": page.Limit, "offset": page.Offset})
}

// owner verifies the authenticated user owns the project + the host belongs
// to it, then returns the Host.
func (h *HostsHandler) owner(c *fiber.Ctx) (*repository.Host, error) {
	projectID := c.Params("id")
	hostID := c.Params("hostId")
	if projectID == "" || hostID == "" {
		_ = c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project id and host id required"})
		return nil, errResponseSent
	}
	_, err := h.Repo.Project.GetByID(c.UserContext(), projectID)
	if err != nil {
		_ = c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
		return nil, errResponseSent
	}
	host, err := h.Repo.Host.GetByID(c.UserContext(), projectID, hostID)
	if err != nil {
		_ = c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "host not found"})
		return nil, errResponseSent
	}
	return host, nil
}
