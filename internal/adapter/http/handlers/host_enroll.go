package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/certutil"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// HostEnrollHandler serves POST /api/internal/host-enroll: the
// host's installer exchanges a CSR and
// its host key for a client certificate bound to that host and one agent.
// Public route (no JWT), registered before the JWT group behind the
// rateEnrollByIP limiter, which runs before the argon2id key check.
type HostEnrollHandler struct {
	Svc *application.HostEnrollment
}

// maxEnrollBodyBytes bounds the JSON body (a CSR is at most
// certutil.MaxCSRPEMBytes).
const maxEnrollBodyBytes = 8 << 10

type hostEnrollBody struct {
	CSRPEM    string `json:"csr_pem"`
	AgentKind string `json:"agent_kind"`
	AgentName string `json:"agent_name"`
}

func enrollError(c *fiber.Ctx, status int, code, msg string) error {
	return c.Status(status).JSON(fiber.Map{"error": msg, "code": code})
}

// Enroll issues the certificate.
//
//	POST /api/internal/host-enroll
//	X-Wafio-Host-Key: wafh_…
//	{"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----…", "agent_kind": "host", "agent_name": "web-1@ebpf"}
func (h *HostEnrollHandler) Enroll(c *fiber.Ctx) error {
	// The response carries a certificate and the request a secret header:
	// nothing on the way may keep either.
	c.Set(fiber.HeaderCacheControl, "no-store")
	key := strings.TrimSpace(c.Get("X-Wafio-Host-Key"))
	if key == "" {
		return enrollError(c, fiber.StatusUnauthorized, "AGENT_AUTH_REQUIRED", "missing X-Wafio-Host-Key header")
	}
	raw := c.Body()
	if len(raw) > maxEnrollBodyBytes {
		return enrollError(c, fiber.StatusBadRequest, "INVALID_BODY", "request body too large")
	}
	var body hostEnrollBody
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		return enrollError(c, fiber.StatusBadRequest, "INVALID_BODY", "body must be JSON with csr_pem, agent_kind and agent_name")
	}

	resp, err := h.Svc.Enroll(c.UserContext(), application.HostEnrollRequest{
		HostKey: key, CSRPEM: body.CSRPEM, AgentKind: body.AgentKind, AgentName: body.AgentName,
		SourceIP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
	})
	if err != nil {
		return h.writeErr(c, err)
	}
	return c.Status(fiber.StatusCreated).JSON(resp)
}

// writeErr maps an enrollment error to its status and code. The host key is
// never logged.
func (h *HostEnrollHandler) writeErr(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, application.ErrEnrollAgentKind):
		return enrollError(c, fiber.StatusBadRequest, "INVALID_AGENT_KIND", application.ErrEnrollAgentKind.Error())
	case errors.Is(err, application.ErrEnrollAgentName):
		return enrollError(c, fiber.StatusBadRequest, "INVALID_AGENT_NAME", application.ErrEnrollAgentName.Error())
	case errors.Is(err, certutil.ErrInvalidCSR):
		return enrollError(c, fiber.StatusBadRequest, "INVALID_CSR", clientText(err, "invalid CSR"))
	case errors.Is(err, domain.ErrHostKeyInvalid):
		slog.Warn("host_enroll_auth_failed", "ip", c.IP())
		return enrollError(c, fiber.StatusUnauthorized, "AGENT_AUTH_FAILED", "invalid host key")
	case errors.Is(err, application.ErrEnrollKeyCheckUnavailable):
		return enrollError(c, fiber.StatusServiceUnavailable, "AGENT_AUTH_UNAVAILABLE", "host key check unavailable; retry")
	case errors.Is(err, domain.ErrEnrollHostRevoked):
		return enrollError(c, fiber.StatusUnauthorized, "AGENT_REVOKED", "host revoked")
	case errors.Is(err, domain.ErrEnrollWindowClosed):
		return enrollError(c, fiber.StatusGone, "ENROLL_EXPIRED",
			"the host key's enrollment window is closed; rotate the host key in the dashboard (it opens a 24-hour window) and run the install command again")
	case errors.Is(err, domain.ErrEnrollLimit):
		return enrollError(c, fiber.StatusConflict, "ENROLL_LIMIT",
			"this host already has the maximum number of enrolled credentials; revoke one on the Credentials page or re-enroll an existing agent name")
	case errors.Is(err, domain.ErrEnrollAgentNameTaken):
		return enrollError(c, fiber.StatusConflict, "AGENT_NAME_TAKEN",
			"this agent name is already used in the project (by another host, by an agent registered without a host, or by the other agent kind); choose another --agent-name or delete the old agent")
	case errors.Is(err, domain.ErrEnrollUsed):
		return enrollError(c, fiber.StatusConflict, "ENROLL_USED",
			"this agent already enrolled with the current host key; to renew it, rotate the host key and run the install command again (if you did not enroll it, revoke its credential on the Credentials page and rotate the key)")
	case errors.Is(err, domain.ErrEnrollUnavailable):
		return enrollError(c, fiber.StatusServiceUnavailable, "ENROLL_UNAVAILABLE",
			"enrollment unavailable: the control plane has no agent CA (agent gRPC listener disabled)")
	}
	slog.Error("host_enroll_failed", "ip", c.IP(), "err", err)
	return enrollError(c, fiber.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
}
