package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// defaultAgentGRPCPort is the agent gRPC port when server.agent_grpc_addr
// names none.
const defaultAgentGRPCPort = 9090

// agentConnectInfo is GET /agent-connect-info: the values an installer asks
// for when connecting a host agent. Every value is already sent
// to each agent (the CA and the server name are in its TLS handshake).
type agentConnectInfo struct {
	GRPCEndpoint         *string              `json:"grpc_endpoint"`
	GRPCServerName       string               `json:"grpc_server_name"`
	GRPCDomainConfigured bool                 `json:"grpc_domain_configured"`
	CASHA256             *string              `json:"ca_sha256"`
	ControlPlaneVersion  string               `json:"control_plane_version"`
	Enrollment           agentEnrollmentLimit `json:"enrollment"`
}

// agentEnrollmentLimit states the host-key enrollment limits
// so the connect guide does not hard-code them.
type agentEnrollmentLimit struct {
	WindowHours           int `json:"window_hours"`
	MaxCredentialsPerHost int `json:"max_credentials_per_host"`
	CertValidityDays      int `json:"cert_validity_days"`
}

func enrollmentLimits() agentEnrollmentLimit {
	return agentEnrollmentLimit{
		WindowHours:           int(domain.HostEnrollWindow / time.Hour),
		MaxCredentialsPerHost: domain.MaxEnrolledCredentialsPerHost,
		CertValidityDays:      int(domain.EnrolledCertValidity / (24 * time.Hour)),
	}
}

// caCertReader reads the global agent CA certificate without its key
// (repository.AgentGRPCRepo).
type caCertReader interface {
	GetGlobalCACertPEM(ctx context.Context) (string, error)
}

// grpcEndpoint is "<grpc_domain>:<port>", or "" when grpc_domain is unset.
func (h *AgentCredentialHandler) grpcEndpoint() string {
	return AgentGRPCEndpoint(h.GRPCDomain, h.GRPCPort)
}

// AgentGRPCEndpoint is "<grpcDomain>:<port>" (port 0 = 9090), or "" when
// grpcDomain is empty: the address agents dial.
func AgentGRPCEndpoint(grpcDomain string, port uint16) string {
	name := strings.TrimSpace(grpcDomain)
	if name == "" {
		return ""
	}
	p := int(port)
	if p == 0 {
		p = defaultAgentGRPCPort
	}
	return net.JoinHostPort(name, strconv.Itoa(p))
}

// AgentGRPCServerName is the name in the gRPC server certificate agents
// verify: server.grpc_domain, or localhost when it is unset
// (cmd/wafio/serve.go).
func AgentGRPCServerName(grpcDomain string) string {
	if name := strings.TrimSpace(grpcDomain); name != "" {
		return name
	}
	return "localhost"
}

// caFingerprint is the lowercase hex SHA-256 of the global agent CA
// certificate (DER); "" when no CA exists yet. It never creates the CA.
func (h *AgentCredentialHandler) caFingerprint(ctx context.Context) (string, error) {
	var src caCertReader = h.CACerts
	if src == nil {
		src = h.Repo.AgentGRPC
	}
	certPEM, err := src.GetGlobalCACertPEM(ctx)
	if errors.Is(err, repository.ErrAgentGRPCCANotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", errors.New("agent CA certificate is not PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

// ConnectInfo returns the gRPC endpoint, the server name agents must verify
// and the CA fingerprint, for the dashboard's "Connect this host" guide.
//
//	GET /api/projects/:id/agent-connect-info
func (h *AgentCredentialHandler) ConnectInfo(c *fiber.Ctx) error {
	out := agentConnectInfo{
		GRPCServerName:       AgentGRPCServerName(h.GRPCDomain),
		GRPCDomainConfigured: strings.TrimSpace(h.GRPCDomain) != "",
		ControlPlaneVersion:  h.ControlPlaneVersion,
		Enrollment:           enrollmentLimits(),
	}
	if ep := h.grpcEndpoint(); ep != "" {
		out.GRPCEndpoint = &ep
	}
	fp, err := h.caFingerprint(c.UserContext())
	if err != nil {
		slog.Error("agent_connect_info_ca_failed", "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error", "code": "INTERNAL_ERROR"})
	}
	if fp != "" {
		out.CASHA256 = &fp
	}
	return c.JSON(out)
}
