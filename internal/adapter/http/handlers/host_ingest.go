package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/validate"
	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

// ──────────────────────────────────────────────────────────────────────────────
// HostIngestHandler — receives telemetry pushed from agents, stores in PostgreSQL.
// ──────────────────────────────────────────────────────────────────────────────
//
// Endpoint: POST /api/internal/host/ingest (authenticated via X-Wafio-Host-Key)
//
// The agent sends a PushPayload JSON body with all telemetry data.
// The handler validates the API key, resolves the agent, and writes to DB.

// GRPCPolicyPusher is the interface the ingest handler uses to push
// trace policies and eBPF state to connected agents via gRPC.
// Implemented by *agentserver.Server.
type GRPCPolicyPusher interface {
	PushTracePoliciesViaGRPC(agentID, projectID string)
	SendEBPFStateViaGRPC(agentID, projectID string, state json.RawMessage)
}

type HostIngestHandler struct {
	Repo    *repository.Repository
	GRPCSrv GRPCPolicyPusher
}

// RequireAgentKey validates the bearer credentials presented by an agent.
//
// The only accepted credential header is:
//
//  1. `X-Wafio-Host-Key` (required) — resolves the owning host via an
//     argon2id hash lookup, then upserts a per-kind agent row so the
//     rest of the pipeline keeps the existing agent_id contract. Kind is
//     inferred from the route path (…/ebpf/… vs. …/waf/…).
//
// On success the middleware populates `agent_id`, `agent_user_id`,
// `host_id` and `project_id` in Fiber Locals.
func (h *HostIngestHandler) RequireAgentKey() fiber.Handler {
	return func(c *fiber.Ctx) error {
		kind := inferAgentKindFromPath(c.Path())

		if hostKey := c.Get("X-Wafio-Host-Key"); hostKey != "" {
			return h.authorizeWithHostKey(c, kind, hostKey)
		}

		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "missing X-Wafio-Host-Key header",
			"code":  "AGENT_AUTH_REQUIRED",
		})
	}
}

// authorizeWithHostKey resolves the Host Key to a host row, ensures there is
// an agent record for (host_id, kind, name), and wires it into Locals.
func (h *HostIngestHandler) authorizeWithHostKey(c *fiber.Ctx, kind, rawKey string) error {
	host, err := h.Repo.Host.VerifyKey(c.UserContext(), rawKey)
	if err != nil && !errors.Is(err, repository.ErrHostKeyInvalid) {
		// A database error or no verification slot says nothing about the
		// key; the agent retries.
		log.Printf("[host_ingest] host key check failed: %v", err)
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "host key check unavailable; retry",
			"code":  "AGENT_AUTH_UNAVAILABLE",
		})
	}
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "invalid host key",
			"code":  "AGENT_AUTH_FAILED",
		})
	}
	if host.Status == "revoked" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "host revoked",
			"code":  "AGENT_REVOKED",
		})
	}

	agentName := c.Get("X-Wafio-Agent-Name")
	if len(agentName) > 255 || !validate.PlainText(agentName) { // agents.name is VARCHAR(255)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "X-Wafio-Agent-Name must be at most 255 characters without control, formatting or bidi characters",
			"code":  "VALIDATION_FAILED",
		})
	}
	if agentName == "" {
		switch kind {
		case "waf":
			// Default to hostname + "@waf" so multiple WAF processes running
			// on the same host end up with stable-but-distinct agent rows
			// even when operators forget to set the header.
			agentName = host.Name + "@waf"
		default:
			agentName = host.Name + "@ebpf"
		}
	}
	agentID, err := h.Repo.EBPF.UpsertAgentForHost(c.UserContext(), host.ID, host.UserID, host.ProjectID, kind, agentName)
	if errors.Is(err, repository.ErrAgentLimit) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "agent limit reached for the project",
			"code":  "AGENT_LIMIT_REACHED",
		})
	}
	if err != nil {
		// The driver error names tables and constraints; keep it server-side.
		log.Printf("[host_ingest] upsert agent for host %s: %v", host.ID, err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to resolve agent",
			"code":  "AGENT_RESOLVE_FAILED",
		})
	}
	c.Locals("agent_id", agentID)
	c.Locals("agent_user_id", host.UserID)
	c.Locals("host_id", host.ID)
	c.Locals("project_id", host.ProjectID)
	c.Locals("agent_kind", kind)

	// Touch host heartbeat + legacy callback URL bookkeeping in the
	// background so the handler doesn't pay DB latency.
	listenAddr := c.Get("X-Agent-Listen")
	sourceIP := c.IP()
	hostID := host.ID
	projectID := host.ProjectID
	go func() {
		// Detached from the request context (the handler returns immediately),
		// but bounded so a stalled DB can't leak this goroutine indefinitely.
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.Repo.Host.TouchHeartbeat(bgCtx, projectID, hostID)
		if listenAddr != "" {
			_, port, _ := net.SplitHostPort(listenAddr)
			if port == "" {
				port = "9999"
			}
			cbURL := "http://" + net.JoinHostPort(sourceIP, port)
			_ = h.Repo.EBPF.UpdateAgentCallbackURL(bgCtx, projectID, agentID, cbURL)
		} else {
			_ = h.Repo.EBPF.TouchAgentLastSeen(bgCtx, projectID, agentID)
		}
	}()
	return c.Next()
}

// inferAgentKindFromPath returns the agent kind (`"host"` or `"waf"`) based
// on the URL path prefix. Used when the client omits the explicit
// X-Wafio-Agent-Kind header.
func inferAgentKindFromPath(path string) string {
	if len(path) >= len("/api/internal/waf") && path[:len("/api/internal/waf")] == "/api/internal/waf" {
		return "waf"
	}
	return "host"
}

// Ingest receives and stores telemetry from an agent.
//
//	POST /api/internal/host/ingest
func (h *HostIngestHandler) Ingest(c *fiber.Ctx) error {
	agentID, ok := c.Locals("agent_id").(string)
	if !ok || agentID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "agent not authenticated"})
	}
	hostID, _ := c.Locals("host_id").(string)
	projectID, _ := c.Locals("project_id").(string)

	var p application.HostTelemetryPayload
	if err := c.BodyParser(&p); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid payload",
		})
	}

	if err := NewHostTelemetryIngest(h.Repo, h.GRPCSrv).IngestDecoded(c.UserContext(), projectID, agentID, hostID, &p); err != nil {
		return c.Status(fiber.StatusMultiStatus).JSON(fiber.Map{
			"status":  "partial",
			"message": "some data ingested with errors",
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// NewHostTelemetryIngest wires the host telemetry ingest service to the
// PostgreSQL repositories. pusher is the agent gRPC server used for
// trace-policy resync; it is passed through unchanged.
func NewHostTelemetryIngest(repo *repository.Repository, pusher GRPCPolicyPusher) *application.HostTelemetryIngest {
	svc := &application.HostTelemetryIngest{
		Telemetry:    repo.EBPF,
		Hosts:        repo.Host,
		Rules:        repo.DetectionRules,
		Incidents:    repo.Incident,
		FirewallHits: NewFirewallRuleHitMerger(repo),
		Policies:     pusher,
	}
	return svc
}

// NewFirewallRuleHitMerger returns the port that merges live BPF hit counts
// into the persisted eBPF desired state.
func NewFirewallRuleHitMerger(repo *repository.Repository) domain.FirewallRuleHitMerger {
	return firewallRuleHitMerger{repo: repo}
}

// firewallRuleHitMerger merges live BPF hit counts into the persisted eBPF
// desired state. It lives next to ebpfDesiredState, which the application
// layer cannot import.
type firewallRuleHitMerger struct{ repo *repository.Repository }

func (m firewallRuleHitMerger) MergeFirewallRuleHits(ctx context.Context, projectID, agentID string, stats *domain.HostRuleStats) error {
	raw, err := m.repo.EBPF.GetDesiredState(ctx, agentID)
	if err != nil {
		return err
	}
	var s ebpfDesiredState
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}

	// Build index maps for O(1) lookup
	blMap := make(map[string]uint32, len(stats.Blocklist))
	for _, e := range stats.Blocklist {
		blMap[e.IP] = e.HitCount
	}
	alMap := make(map[string]uint32, len(stats.Allowlist))
	for _, e := range stats.Allowlist {
		alMap[e.IP] = e.HitCount
	}
	ppKey := func(port uint16, proto, dir string) string {
		return fmt.Sprintf("%d/%s/%s", port, proto, dir)
	}
	ppMap := make(map[string]uint64, len(stats.PortPolicies))
	for _, p := range stats.PortPolicies {
		ppMap[ppKey(p.Port, p.Proto, p.Direction)] = p.HitCount
	}
	egMap := make(map[string]uint32, len(stats.EgressBlocklist))
	for _, e := range stats.EgressBlocklist {
		egMap[e.IP] = e.HitCount
	}

	changed := false
	for i := range s.Blocklist {
		if hc, ok := listEntryHits(blMap, s.Blocklist[i].IP); ok && s.Blocklist[i].HitCount != hc {
			s.Blocklist[i].HitCount = hc
			changed = true
		}
	}
	for i := range s.Allowlist {
		if hc, ok := listEntryHits(alMap, s.Allowlist[i].IP); ok && s.Allowlist[i].HitCount != hc {
			s.Allowlist[i].HitCount = hc
			changed = true
		}
	}
	for i := range s.PortPolicies {
		k := ppKey(s.PortPolicies[i].Port, s.PortPolicies[i].Proto, s.PortPolicies[i].Direction)
		if hc, ok := ppMap[k]; ok && s.PortPolicies[i].HitCount != hc {
			s.PortPolicies[i].HitCount = hc
			changed = true
		}
	}
	for i := range s.EgressBlocklist {
		if hc, ok := listEntryHits(egMap, s.EgressBlocklist[i].IP); ok && s.EgressBlocklist[i].HitCount != hc {
			s.EgressBlocklist[i].HitCount = hc
			changed = true
		}
	}

	if changed {
		updated, err := json.Marshal(s)
		if err != nil {
			return err
		}
		if err := m.repo.EBPF.SetDesiredState(ctx, projectID, agentID, updated); err != nil {
			log.Printf("[ingest] hit count update error: %v", err)
		}
	}
	return nil
}

// listEntryHits sums the live hit counts of the map entries a desired list
// entry occupies (the agent reports one entry per prefix in canonical
// spelling, so "192.0.2.7/24" and a range match their prefixes). ok is false
// when the agent reported none of them.
func listEntryHits(live map[string]uint32, entry string) (uint32, bool) {
	keys, err := hostpolicy.IPListKeys(entry)
	if err != nil {
		hc, ok := live[entry]
		return hc, ok
	}
	var sum uint64
	found := false
	for _, k := range keys {
		if hc, ok := live[k]; ok {
			sum += uint64(hc)
			found = true
		}
	}
	if sum > math.MaxUint32 {
		sum = math.MaxUint32
	}
	return uint32(sum), found
}
