package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/agentserver"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/validate"
	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

// ──────────────────────────────────────────────────────────────────────────────
// HostPolicyHandler — DB-backed eBPF data handler for server-side API.
// Reads telemetry from PostgreSQL (pushed by agents) and serves to frontend.
// ──────────────────────────────────────────────────────────────────────────────

type HostPolicyHandler struct {
	Repo        *repository.Repository
	GRPCSrv     GRPCPolicyPusher // optional; set in serve.go to enable gRPC policy push
	GeoEnricher GeoEnricher      // optional; used for GeoIP enrichment of top attacker IPs
	// GeoRanges: optional; the control plane's GeoIP country database, for
	// the geo capacity check at save (geoCapacityCheck).
	GeoRanges GeoRangeSource
	// ControlPlanePort is the agent gRPC port named in the egress Deny All
	// warning (server.agent_grpc_addr); 0 = 9090.
	ControlPlanePort uint16

	// analytics owns the Firewall analytics caches and warmer.
	analyticsOnce sync.Once
	analytics     *application.FirewallAnalytics
}

// firewallAnalytics returns the handler's analytics service, built on first
// use from the handler's dependencies.
func (h *HostPolicyHandler) firewallAnalytics() *application.FirewallAnalytics {
	h.analyticsOnce.Do(func() { h.analytics = NewFirewallAnalytics(h.Repo, h.GeoEnricher) })
	return h.analytics
}

// NewFirewallAnalytics wires the Firewall analytics service to the
// repositories. The port-policy count reads the desired state the same way
// the policy handlers do.
func NewFirewallAnalytics(repo *repository.Repository, geoEnricher GeoEnricher) *application.FirewallAnalytics {
	svc := &application.FirewallAnalytics{
		Geo:          geoEnricher,
		PortPolicies: portPolicyCounter{h: &HostPolicyHandler{Repo: repo}},
	}
	if repo != nil {
		svc.Store = repo.EBPF
	}
	return svc
}

// StartFirewallCacheWarmer starts the Firewall analytics cache warmer.
func (h *HostPolicyHandler) StartFirewallCacheWarmer(ctx context.Context) {
	h.firewallAnalytics().StartFirewallCacheWarmer(ctx)
}

// portPolicyCounter implements domain.FirewallPortPolicyCounter on the
// eBPF desired state, which the application layer cannot decode.
type portPolicyCounter struct{ h *HostPolicyHandler }

func (p portPolicyCounter) PortPolicyCount(ctx context.Context, agentID string) (int, error) {
	s, err := p.h.readState(ctx, agentID)
	if err != nil {
		return 0, err
	}
	return len(s.PortPolicies), nil
}

// validateIPEntry accepts a plain IP ("1.2.3.4"), CIDR ("1.2.3.0/24"),
// or dash-range ("1.2.3.1-1.2.3.50"). Returns an error for anything else.
func validateIPEntry(s string) error {
	_, err := hostpolicy.IPListPrefixes(s)
	return err
}

// ipListError answers a list that cannot be stored: 400 IP_LIST_FULL when it
// does not fit its map (the agent's maps never evict an operator entry to
// make room, so the change is refused here), INVALID_IP otherwise.
func ipListError(c *fiber.Ctx, list string, err error) error {
	if errors.Is(err, hostpolicy.ErrIPListCapacity) {
		return writeClientError(c, "IP_LIST_FULL", fmt.Errorf("the %s is full: %w", list, err),
			"The list is full; remove entries or merge addresses into prefixes.")
	}
	return invalidInput(c, "INVALID_IP", err)
}

// validatePolicyIPs checks a whole list against its map: the agent stores
// prefixes natively, so capacity counts distinct prefixes: an IPv6 /64
// or an IPv4 /15 is one entry, a range its minimal CIDR cover.
func validatePolicyIPs(entries []string, capacity int) error {
	_, err := hostpolicy.CountIPListPrefixes(entries, capacity)
	return err
}

// pushPoliciesAfterChange triggers a gRPC push of all persisted trace policies
// for the given agent to any currently connected host agent stream.
// Called after Create/Update/Delete so changes take effect immediately.
func (h *HostPolicyHandler) pushPoliciesAfterChange(agentID string) {
	if h.GRPCSrv == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		agent, err := h.Repo.EBPF.GetAgentByID(ctx, agentID)
		if err != nil || agent == nil {
			return
		}
		h.GRPCSrv.PushTracePoliciesViaGRPC(agentID, agent.ProjectID)
	}()
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// resolveProjectID extracts the project ID from ":id" route param and verifies
// the authenticated user owns the project.
func (h *HostPolicyHandler) resolveProjectID(c *fiber.Ctx) (string, error) {
	projectID := c.Params("id")
	if projectID == "" {
		return "", newPublicError(fiber.StatusBadRequest, "BAD_REQUEST", "project id required")
	}
	if _, err := h.Repo.Project.GetByID(c.UserContext(), projectID); err != nil {
		return "", errProjectNotFound
	}
	return projectID, nil
}

// resolveAgentID turns ?agent_id= or ?host_id= into an agent id.
//
// Both come from the query string, so both are the caller's choice, and neither
// used to be checked against the project on the route. A member of any project
// could name another tenant's agent or host and every handler downstream --
// nineteen of them go through here -- would operate on it. That is a cross-tenant leak, in
// a resolver rather than a query.
//
// Cross-tenant misses return 404 rather than 403, per the project's rule: 403
// confirms the id exists.
func (h *HostPolicyHandler) resolveAgentID(c *fiber.Ctx) (string, error) {
	return h.resolveTargetAgent(c, false)
}

// errHostTargetRequired: a write without ?agent_id= or ?host_id= in a project
// with more than one host agent. Reads still fall back to the most
// recently seen agent; a write must never land on whichever host reported
// last.
var errHostTargetRequired = newPublicError(fiber.StatusBadRequest, "HOST_TARGET_REQUIRED",
	"This project has more than one host. Name the host to change with agent_id or host_id.")

// resolveTargetAgent is resolveAgentID; write = true refuses the
// most-recently-seen fallback when the project has more than one host agent.
func (h *HostPolicyHandler) resolveTargetAgent(c *fiber.Ctx, write bool) (string, error) {
	projectID, err := h.resolveProjectID(c)
	if err != nil {
		return "", err
	}
	if agentID := c.Query("agent_id"); agentID != "" {
		agent, err := h.Repo.EBPF.GetAgentByID(c.UserContext(), agentID)
		if err != nil || agent == nil || agent.ProjectID != projectID {
			return "", errAgentNotFound
		}
		return agentID, nil
	}
	// A host id may stand in for an agent id, so the frontend does not need a
	// separate resolution round-trip. It is scoped the same way.
	if hostID := c.Query("host_id"); hostID != "" {
		agents, err := h.Repo.EBPF.ListNonWAFAgentsByHostInProject(c.UserContext(), hostID, projectID)
		if err == nil && len(agents) > 0 {
			return agents[0].ID, nil
		}
		return "", errAgentNotFound
	}
	agents, err := h.Repo.EBPF.ListAgentsByProject(c.UserContext(), projectID)
	if err != nil {
		return "", &PublicError{Status: fiber.StatusInternalServerError, Code: "INTERNAL_ERROR", Message: "internal error", Cause: err}
	}
	return fallbackAgent(agents, write)
}

// fallbackAgent picks the agent for a request that named none: the most
// recently seen one (agents arrive in last_seen order), except that a write
// in a project with more than one host agent must name its target.
func fallbackAgent(agents []repository.EBPFAgent, write bool) (string, error) {
	if len(agents) == 0 {
		// A project without a host agent is an empty state, not a failure:
		// the dashboard keys its "register a host" view on NO_AGENTS.
		return "", errNoHostAgents
	}
	if write && len(agents) > 1 {
		return "", errHostTargetRequired
	}
	return agents[0].ID, nil
}

// ── Desired-state helpers ────────────────────────────────────────────────────

// ebpfDesiredState is the authoritative configuration stored in agents.desired_state.
// It is the single source of truth for all mutable eBPF settings. On every write
// the updated blob is persisted to DB and pushed to the agent via gRPC.
type ebpfDesiredState struct {
	Revision         int64                             `json:"_revision,omitempty,string"`
	Config           *hostpolicy.FullConfigAPI         `json:"config,omitempty"`
	Blocklist        []hostpolicy.BlocklistEntry       `json:"blocklist"`
	Allowlist        []hostpolicy.AllowlistEntry       `json:"allowlist"`
	GeoBlocked       []hostpolicy.CountryEntry         `json:"geo_blocked"`
	PortPolicies     []hostpolicy.PortPolicyAPI        `json:"port_policies"`
	PortPolicyConfig *hostpolicy.PortPolicyConfigAPI   `json:"port_policy_config,omitempty"`
	EgressBlocklist  []hostpolicy.EgressBlocklistEntry `json:"egress_blocklist"`
	TraceConfig      *hostpolicy.TraceConfigAPI        `json:"trace_config,omitempty"`
	// Geo mode: "block" (absent in states saved before allow mode)
	// uses GeoBlocked; "allow" drops every public source outside GeoAllowed.
	// The allowed countries have a key of their own, so a host agent older
	// than allow mode ignores them instead of blocking them. The
	// acknowledgement is the dashboard confirm dialog's (lockout guard).
	GeoMode              string   `json:"geo_mode,omitempty"`
	GeoAllowed           []string `json:"geo_allowed,omitempty"`
	GeoAllowAcknowledged bool     `json:"geo_allow_acknowledged,omitempty"`
}

// prunedBlocklist removes expired entries from a blocklist slice, returning
// an empty (non-nil) slice if all entries were pruned.
func prunedBlocklist(entries []hostpolicy.BlocklistEntry) []hostpolicy.BlocklistEntry {
	now := time.Now()
	out := entries[:0]
	for _, e := range entries {
		if e.ExpiresAt != nil && !e.ExpiresAt.After(now) {
			continue // skip expired
		}
		out = append(out, e)
	}
	if out == nil {
		out = []hostpolicy.BlocklistEntry{}
	}
	return out
}

// prunedEgressBlocklist removes expired entries from an egress blocklist slice.
func prunedEgressBlocklist(entries []hostpolicy.EgressBlocklistEntry) []hostpolicy.EgressBlocklistEntry {
	now := time.Now()
	out := entries[:0]
	for _, e := range entries {
		if e.ExpiresAt != nil && !e.ExpiresAt.After(now) {
			continue // skip expired
		}
		out = append(out, e)
	}
	if out == nil {
		out = []hostpolicy.EgressBlocklistEntry{}
	}
	return out
}

// prunedAllowlist removes expired entries from an allowlist slice.
func prunedAllowlist(entries []hostpolicy.AllowlistEntry) []hostpolicy.AllowlistEntry {
	now := time.Now()
	out := entries[:0]
	for _, e := range entries {
		if e.ExpiresAt != nil && !e.ExpiresAt.After(now) {
			continue
		}
		out = append(out, e)
	}
	if out == nil {
		out = []hostpolicy.AllowlistEntry{}
	}
	return out
}

// readState loads the desired state from the DB for the given agent.
func (h *HostPolicyHandler) readState(ctx context.Context, agentID string) (*ebpfDesiredState, error) {
	raw, err := h.Repo.EBPF.GetDesiredState(ctx, agentID)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' {
		return nil, fmt.Errorf("desired state must be an object")
	}
	var s ebpfDesiredState
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// writeState runs the firewall lockout guard, then persists the
// desired state and pushes it to the agent via gRPC. A rejected state is
// never stored, so the dashboard shows the lockout error before any push;
// the agent repeats the same guard before touching a map. Warnings describe
// accepted states that still block something operators usually rely on.
func (h *HostPolicyHandler) writeState(ctx context.Context, agentID, projectID string, s *ebpfDesiredState) ([]hostpolicy.FirewallWarning, error) {
	sshPorts := h.agentSSHPorts(ctx, projectID, agentID)
	var features []string
	if hostpolicy.HasScopedAllowlistEntry(s.Allowlist) {
		features = h.agentFirewallFeatures(ctx, projectID, agentID)
	}
	warnings, err := h.validateStateFor(s, sshPorts, features)
	if err != nil {
		return nil, err
	}
	if err := h.storeState(ctx, agentID, projectID, s); err != nil {
		return nil, err
	}
	return warnings, nil
}

// validateStateFor is the firewall lockout guard for one host:
// its sshd ports (nil = 22 assumed) and its reported firewall features. It
// reads nothing; a refusal is returned before anything is stored. The
// single-host handlers and the multi-host apply share it.
func (h *HostPolicyHandler) validateStateFor(s *ebpfDesiredState, sshPorts []uint16, features []string) ([]hostpolicy.FirewallWarning, error) {
	normalizeGeoState(s)
	return hostpolicy.ValidateFirewallSafety(hostpolicy.FirewallSafetyInput{
		Config:               s.Config,
		PortPolicyConfig:     s.PortPolicyConfig,
		PortPolicies:         s.PortPolicies,
		Blocklist:            s.Blocklist,
		Allowlist:            s.Allowlist,
		EgressBlocklist:      s.EgressBlocklist,
		SSHPorts:             sshPorts,
		ControlPlanePort:     h.ControlPlanePort,
		GeoMode:              s.GeoMode,
		GeoAllowed:           s.GeoAllowed,
		GeoAllowAcknowledged: s.GeoAllowAcknowledged,
		// A host that cannot enforce port scopes drops scoped entries
		// before its own check; judge the state the way it will.
		AllowlistPortsUnsupported: hostpolicy.HasScopedAllowlistEntry(s.Allowlist) &&
			!slices.Contains(features, hostpolicy.AllowlistFeaturePorts),
	})
}

// storeState persists a guarded desired state with the revision CAS
// (repository.ErrDesiredStateConflict when it changed since it was read)
// and pushes the stored state to the agent over gRPC.
func (h *HostPolicyHandler) storeState(ctx context.Context, agentID, projectID string, s *ebpfDesiredState) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	stored, err := h.Repo.EBPF.CompareAndSwapDesiredState(ctx, projectID, agentID, s.Revision, raw)
	if err != nil {
		return err
	}
	s.Revision, _ = repository.DesiredStateRevision(stored)
	if h.GRPCSrv != nil {
		h.GRPCSrv.SendEBPFStateViaGRPC(agentID, projectID, stored)
	}
	return nil
}

// ── Desired-state mutators ──────────────────────────────────────────────────
// Each changes one list of a desired state; the single-host handlers and the
// multi-host apply (host_bulk_apply.go) call the same functions.

// Capacities of the desired-state IP lists (prefixes).
const (
	blocklistCapacity = 100000
	allowlistCapacity = 10000
)

// addBlocklist upserts entries by ip (a re-add refreshes added_at and
// restarts its TTL) and checks the list against its map capacity.
func addBlocklist(s *ebpfDesiredState, entries []hostpolicy.IPEntry, now time.Time) error {
	existing := make(map[string]int, len(s.Blocklist))
	for i, e := range s.Blocklist {
		existing[e.IP] = i
	}
	for _, e := range entries {
		entry := hostpolicy.BlocklistEntry{IP: strings.TrimSpace(e.IP), AddedAt: now}
		if e.TTLMs > 0 {
			exp := now.Add(time.Duration(e.TTLMs) * time.Millisecond)
			entry.ExpiresAt = &exp
		}
		if idx, ok := existing[entry.IP]; ok {
			s.Blocklist[idx] = entry
		} else {
			s.Blocklist = append(s.Blocklist, entry)
		}
	}
	ips := make([]string, 0, len(s.Blocklist))
	for _, entry := range s.Blocklist {
		ips = append(ips, entry.IP)
	}
	return validatePolicyIPs(ips, blocklistCapacity)
}

// removeBlocklist drops entries whose ip matches exactly and returns how many
// it removed.
func removeBlocklist(s *ebpfDesiredState, ips []string) int {
	remove := make(map[string]bool, len(ips))
	for _, ip := range ips {
		remove[ip] = true
	}
	before := len(s.Blocklist)
	filtered := s.Blocklist[:0]
	for _, e := range s.Blocklist {
		if !remove[e.IP] {
			filtered = append(filtered, e)
		}
	}
	s.Blocklist = filtered
	return before - len(filtered)
}

// addAllowlist upserts entries by identity (upsertAllowlist) and checks the
// list against its capacity; it returns the audit records of the add.
func addAllowlist(s *ebpfDesiredState, entries []hostpolicy.IPEntry, now time.Time) ([]map[string]any, error) {
	var audit []map[string]any
	s.Allowlist, audit = upsertAllowlist(s.Allowlist, entries, now)
	ips := make([]string, 0, len(s.Allowlist))
	for _, entry := range s.Allowlist {
		ips = append(ips, entry.IP)
	}
	return audit, validatePolicyIPs(ips, allowlistCapacity)
}

// removeAllowlist drops entries matching an ip exactly or by identity (any
// spelling of the same prefixes) and returns how many it removed.
func removeAllowlist(s *ebpfDesiredState, ips []string) int {
	remove := make(map[string]bool, 2*len(ips))
	for _, ip := range ips {
		remove[ip] = true
		remove[allowlistIdentity(ip)] = true
	}
	before := len(s.Allowlist)
	filtered := s.Allowlist[:0]
	for _, e := range s.Allowlist {
		if !remove[e.IP] && !remove[allowlistIdentity(e.IP)] {
			filtered = append(filtered, e)
		}
	}
	s.Allowlist = filtered
	return before - len(filtered)
}

// errEgressIPv6Unsupported: an IPv6 egress entry for a host whose TC object
// does not filter IPv6.
var errEgressIPv6Unsupported = errors.New("this host's eBPF objects do not filter IPv6 egress traffic; update the host agent and its eBPF objects")

// addEgressBlocklist upserts entries by exact ip (empty ips are skipped) and
// returns how many it took. ipv6Supported is asked only when the list holds
// an IPv6 entry; the capacity check follows the IPv6 gate.
func addEgressBlocklist(s *ebpfDesiredState, entries []hostpolicy.IPEntry, now time.Time, ipv6Supported func() bool) (int, error) {
	added := 0
	// ip → index of its first stored entry (a stored duplicate keeps its
	// later copies untouched, as the former linear scan did).
	index := make(map[string]int, len(s.EgressBlocklist)+len(entries))
	for i, e := range s.EgressBlocklist {
		if _, seen := index[e.IP]; !seen {
			index[e.IP] = i
		}
	}
	for _, r := range entries {
		if r.IP == "" {
			continue
		}
		entry := hostpolicy.EgressBlocklistEntry{IP: r.IP, AddedAt: now}
		if r.TTLMs > 0 {
			exp := now.Add(time.Duration(r.TTLMs) * time.Millisecond)
			entry.ExpiresAt = &exp
		}
		if i, ok := index[r.IP]; ok {
			s.EgressBlocklist[i] = entry
		} else {
			index[r.IP] = len(s.EgressBlocklist)
			s.EgressBlocklist = append(s.EgressBlocklist, entry)
		}
		added++
	}
	ips := make([]string, 0, len(s.EgressBlocklist))
	for _, entry := range s.EgressBlocklist {
		ips = append(ips, entry.IP)
	}
	if hasIPv6Entry(ips) && !ipv6Supported() {
		return added, errEgressIPv6Unsupported
	}
	return added, hostpolicy.ValidateEgressBlocklistCapacity(ips)
}

// removeEgressBlocklist drops entries whose ip matches exactly and returns
// how many it removed.
func removeEgressBlocklist(s *ebpfDesiredState, ips []string) int {
	toRemove := make(map[string]bool, len(ips))
	for _, ip := range ips {
		if ip != "" {
			toRemove[ip] = true
		}
	}
	filtered := s.EgressBlocklist[:0]
	for _, e := range s.EgressBlocklist {
		if !toRemove[e.IP] {
			filtered = append(filtered, e)
		}
	}
	removed := len(s.EgressBlocklist) - len(filtered)
	s.EgressBlocklist = filtered
	return removed
}

// addPortPolicies upserts validated, canonical rules by map slot.
func addPortPolicies(s *ebpfDesiredState, policies []hostpolicy.PortPolicyAPI) {
	s.PortPolicies = upsertPortPolicies(s.PortPolicies, policies)
}

// removePortPolicies drops every stored spelling of each key's map slot;
// it returns how many stored rules it removed.
func removePortPolicies(s *ebpfDesiredState, keys []hostpolicy.PortPolicyAPI) int {
	before := len(s.PortPolicies)
	for _, k := range keys {
		s.PortPolicies = removePortPolicy(s.PortPolicies, k)
	}
	return before - len(s.PortPolicies)
}

// ControlPlanePortFromAddr extracts the port of server.agent_grpc_addr
// (":9090", "0.0.0.0:9090"); 0 (= 9090 in the guard) when it has none.
func ControlPlanePortFromAddr(addr string) uint16 {
	_, portStr, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return 0
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(port)
}

// upsertPortPolicies adds rules by BPF map slot: "" and "any" (or "" and
// "ingress") name one slot, so a new rule replaces every stored spelling of
// it in place, and a rule for a new slot is appended.
func upsertPortPolicies(existing, add []hostpolicy.PortPolicyAPI) []hostpolicy.PortPolicyAPI {
	out := slices.Clone(existing)
	for _, p := range add {
		replaced := false
		kept := out[:0]
		for _, e := range out {
			if hostpolicy.SamePortPolicyKey(e, p) {
				if !replaced {
					kept = append(kept, p)
					replaced = true
				}
				continue
			}
			kept = append(kept, e)
		}
		if !replaced {
			kept = append(kept, p)
		}
		out = kept
	}
	return out
}

// removePortPolicy drops every stored spelling of key's map slot.
func removePortPolicy(existing []hostpolicy.PortPolicyAPI, key hostpolicy.PortPolicyAPI) []hostpolicy.PortPolicyAPI {
	out := make([]hostpolicy.PortPolicyAPI, 0, len(existing))
	for _, p := range existing {
		if !hostpolicy.SamePortPolicyKey(p, key) {
			out = append(out, p)
		}
	}
	return out
}

// agentSSHPorts is the sshd listener set the host agent reported in its
// host info; nil (guard assumes 22) when unknown or unreadable.
func (h *HostPolicyHandler) agentSSHPorts(ctx context.Context, projectID, agentID string) []uint16 {
	if h.Repo == nil || h.Repo.EBPF == nil {
		return nil
	}
	ports, err := h.Repo.EBPF.GetAgentSSHPorts(ctx, projectID, agentID)
	if err != nil {
		slog.Warn("firewall_guard_ssh_ports_unavailable", "agent_id", agentID, "err", err)
		return nil
	}
	return ports
}

// jsonWithWarnings answers v and, when the lockout check produced warnings,
// adds them as a top-level "warnings" array ([{code, message}]).
func jsonWithWarnings(c *fiber.Ctx, v any, warnings []hostpolicy.FirewallWarning) error {
	if len(warnings) == 0 {
		return c.JSON(v)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var body map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep 64-bit values exact through the round trip
	if err := dec.Decode(&body); err != nil {
		return err
	}
	body["warnings"] = warnings
	return c.JSON(body)
}

// resolveAgentAndProject resolves the agent ID and fetches the project ID in
// one shot — required by write handlers that need both for the gRPC push.
// Every write goes through here, so a write names its host when the project
// has more than one (HOST_TARGET_REQUIRED).
func (h *HostPolicyHandler) resolveAgentAndProject(c *fiber.Ctx) (agentID, projectID string, err error) {
	agentID, err = h.resolveTargetAgent(c, true)
	if err != nil {
		return
	}
	agent, err := h.Repo.EBPF.GetAgentByID(c.UserContext(), agentID)
	if err != nil || agent == nil {
		err = errAgentNotFound
		return
	}
	projectID = agent.ProjectID
	return
}

// ── Agent CRUD ──────────────────────────────────────────────────────────────

// RegisterAgent creates a new agent and returns the API key (shown only once).
//
//	POST /api/projects/:id/ebpf/agents  {"name": "production-1"}
func (h *HostPolicyHandler) RegisterAgent(c *fiber.Ctx) error {
	userID, _ := c.Locals("user_id").(string)
	var req struct {
		Name string `json:"name"`
	}
	err := c.BodyParser(&req)
	req.Name = strings.TrimSpace(req.Name)
	if err != nil || req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "name is required",
			"code":  "VALIDATION_FAILED",
		})
	}
	if len(req.Name) > 255 { // agents.name is VARCHAR(255)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name must be at most 255 characters", "code": "VALIDATION_FAILED"})
	}
	if !validate.PlainText(req.Name) {
		return rejectUnsafeName(c, "name")
	}
	projectID, err := h.resolveProjectID(c)
	if err != nil {
		return err
	}

	// Generate a secure random API key (32 bytes = 64 hex chars)
	keyBytes := make([]byte, 32)
	if _, err = rand.Read(keyBytes); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to generate API key",
			"code":  "INTERNAL_ERROR",
		})
	}
	apiKey := hex.EncodeToString(keyBytes)

	// Stored as kind "host" (agents.kind CHECK, migration 000031); this used to
	// insert the pre-000031 "ebpf" and fail on the constraint.
	agent, err := h.Repo.EBPF.RegisterAgentKind(c.UserContext(), userID, projectID, req.Name, apiKey, "host")
	if err != nil {
		if isUniqueViolation(err) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": "An agent with this name already exists in this project.",
				"code":  "CONFLICT",
			})
		}
		slog.Error("host_agent_register_failed", "project_id", projectID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to register agent",
			"code":  "INTERNAL_ERROR",
		})
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: userID,
		Action: repository.AuditAgentRegistered, TargetType: "agent", TargetID: agent.ID, TargetName: req.Name,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
	})
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"agent":   agent,
		"api_key": apiKey, // shown only once
		"warning": "Save this API key securely. It cannot be retrieved again.",
	})
}

// ListAgents returns the project's host agents, paged with ?limit= (≤ 100;
// omitted = up to 100) and ?offset=. "count" is the number returned (kept for
// existing callers), "total" the full count.
//
//	GET /api/projects/:id/host/agents?limit=&offset=
func (h *HostPolicyHandler) ListAgents(c *fiber.Ctx) error {
	projectID, err := h.resolveProjectID(c)
	if err != nil {
		return err
	}
	agents, err := h.Repo.EBPF.ListAgentsByProject(c.UserContext(), projectID)
	if err != nil {
		slog.Error("host_agents_list_failed", "project_id", projectID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "internal error",
			"code":  "INTERNAL_ERROR",
		})
	}
	if agents == nil {
		agents = []repository.EBPFAgent{}
	}
	page := parsePage(c, maxListLimit)
	out := pageOf(agents, page)
	return c.JSON(fiber.Map{
		"agents": out,
		"count":  len(out),
		"total":  len(agents),
		"limit":  page.Limit,
		"offset": page.Offset,
	})
}

// DeleteAgent removes an agent of this project and all its data. Same rules
// as DELETE /api/fleet/agents/:agentId (deleteAgentChecked): project member
// or owner, 404 for an agent of another project, 409 AGENT_ONLINE unless
// ?force=1.
//
//	DELETE /api/projects/:id/host/agents/:agentId[?force=1]
func (h *HostPolicyHandler) DeleteAgent(c *fiber.Ctx) error {
	return deleteAgentChecked(c, h.Repo, c.Params("id"), c.Params("agentId"), h.GRPCSrv)
}

// ── Status ──────────────────────────────────────────────────────────────────

// GetStatus returns the latest eBPF + trace status for an agent.
//
//	GET /api/ebpf/status?agent_id=<uuid>
func (h *HostPolicyHandler) GetStatus(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	requestLiveStatus(h.GRPCSrv, c.Params("id"), agentID)

	// Fetch agent metadata (last_seen, name) so the client can distinguish
	// between "agent registered but never connected", "agent was online but
	// is now stale", and "agent is actively reporting".
	agent, agentErr := h.Repo.EBPF.GetAgentByID(c.UserContext(), agentID)

	// Consider the agent "online" if any telemetry (not just eBPF status)
	// landed within the last 90 seconds. 90s = 3× the 30s heartbeat interval,
	// giving enough buffer for SSE polling delay and minor clock jitter.
	const agentLivenessWindow = 90 * time.Second
	agentOnline := false
	if agentErr == nil && agent != nil && agent.LastSeen != nil {
		agentOnline = time.Since(*agent.LastSeen) <= agentLivenessWindow
	}

	// Fallback: if the gRPC stream is temporarily broken (reconnecting) but
	// the HTTP host-agent heartbeat is still active, consider the agent online.
	// This prevents a false "Agent Offline" banner during brief gRPC reconnects.
	if !agentOnline {
		if hostLastSeen, err := h.Repo.Host.GetAgentHostLastSeen(c.UserContext(), agentID); err == nil && hostLastSeen != nil {
			if time.Since(*hostLastSeen) <= agentLivenessWindow {
				agentOnline = true
			}
		}
	}

	payload, _, err := h.Repo.EBPF.LatestStatus(c.UserContext(), agentID)
	if err != nil {
		if err == pgx.ErrNoRows {
			// No eBPF status row yet. Either the agent was started without
			// --ebpf (in which case it is still online but isn't pushing
			// kernel-firewall status), or it has genuinely never checked in.
			// Surface both facts so the UI can render the right hint.
			resp := fiber.Map{
				"running":        false,
				"never_reported": true,
				"agent_online":   agentOnline,
			}
			if agentErr == nil && agent != nil {
				resp["agent_id"] = agent.ID
				resp["agent_name"] = agent.Name
				if agent.LastSeen != nil {
					resp["agent_last_seen"] = agent.LastSeen
				}
			}
			return c.JSON(resp)
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}

	// The agent pushes status wrapped as {"ebpf": {...}}.
	// The frontend expects the inner object directly, but we also inject
	// liveness fields so the UI doesn't have to hit a second endpoint.
	var wrapper map[string]json.RawMessage
	var innerObj map[string]json.RawMessage
	if err := json.Unmarshal(payload, &wrapper); err == nil {
		if inner, ok := wrapper["ebpf"]; ok {
			_ = json.Unmarshal(inner, &innerObj)
		}
	}
	if innerObj == nil {
		_ = json.Unmarshal(payload, &innerObj)
	}
	if innerObj == nil {
		innerObj = map[string]json.RawMessage{}
	}
	ingestionJSON, _ := json.Marshal(h.Repo.EBPF.IngestionStatus(agentID))
	innerObj["ingestion"] = ingestionJSON
	agentOnlineJSON, _ := json.Marshal(agentOnline)
	innerObj["agent_online"] = agentOnlineJSON
	if agentErr == nil && agent != nil {
		if agent.LastSeen != nil {
			lsJSON, _ := json.Marshal(agent.LastSeen)
			innerObj["agent_last_seen"] = lsJSON
		}
		nameJSON, _ := json.Marshal(agent.Name)
		innerObj["agent_name"] = nameJSON
	}
	if reader, ok := h.GRPCSrv.(interface {
		HostBundleStatus(string, string) map[string]agentserver.HostBundleApplyStatus
	}); ok && agent != nil {
		bundleJSON, _ := json.Marshal(reader.HostBundleStatus(agentID, agent.ProjectID))
		innerObj["bundle_status"] = bundleJSON
	}
	out, _ := json.Marshal(innerObj)
	c.Set("Content-Type", "application/json")
	return c.Send(out)
}

// ── Metrics ─────────────────────────────────────────────────────────────────

// GetMetrics returns the latest aggregated metrics for an agent.
//
//	GET /api/ebpf/metrics?agent_id=<uuid>
func (h *HostPolicyHandler) GetMetrics(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	requestLiveStatus(h.GRPCSrv, c.Params("id"), agentID)
	m, err := h.Repo.EBPF.LatestMetrics(c.UserContext(), agentID)
	if err != nil {
		if err == pgx.ErrNoRows {
			// Return JSON null (not {}) so the frontend can reliably detect "no metrics yet"
			// via a single falsy check. An empty object is truthy and causes the UI to
			// attempt to render hero cards with undefined numeric fields.
			c.Set("Content-Type", "application/json")
			return c.Send([]byte("null"))
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	return c.JSON(m)
}

// ── Events ──────────────────────────────────────────────────────────────────

// GetEvents returns recent firewall events for an agent. ?limit= defaults to
// 100 and is capped at 1000.
//
//	GET /api/projects/:id/host/events?agent_id=<uuid>&limit=100
func (h *HostPolicyHandler) GetEvents(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	limit := boundedLimit(c, 100)
	events, err := h.Repo.EBPF.RecentEvents(c.UserContext(), agentID, limit)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	if events == nil {
		events = []repository.EBPFEventRow{}
	}
	return c.JSON(fiber.Map{
		"events": events,
		"count":  len(events),
	})
}

// ── Connections ─────────────────────────────────────────────────────────────

// LiveTelemetryRequester asks a connected host agent of a project to send
// its connections and bandwidth snapshots live (RequestLiveTelemetry), or
// its status, trace stats, rule hit counts and metrics live
// (RequestLiveStatus); agentserver.Server.
type LiveTelemetryRequester interface {
	RequestLiveTelemetry(projectID, agentID string)
	RequestLiveStatus(projectID, agentID string)
}

// requestLiveTelemetry asks for live snapshots of agentID when srv can (a
// nil *agentserver.Server is a no-op there).
func requestLiveTelemetry(srv GRPCPolicyPusher, projectID, agentID string) {
	if r, ok := srv.(LiveTelemetryRequester); ok {
		r.RequestLiveTelemetry(projectID, agentID)
	}
}

// requestLiveStatus asks for live status and metrics of agentID when srv
// can (a nil *agentserver.Server is a no-op there).
func requestLiveStatus(srv GRPCPolicyPusher, projectID, agentID string) {
	if r, ok := srv.(LiveTelemetryRequester); ok {
		r.RequestLiveStatus(projectID, agentID)
	}
}

// ListConnections returns the latest conntrack snapshot for an agent.
// ?limit= defaults to 100 and is capped at 1000.
//
//	GET /api/projects/:id/host/connections?agent_id=<uuid>&limit=100
func (h *HostPolicyHandler) ListConnections(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	limit := boundedLimit(c, 100)
	requestLiveTelemetry(h.GRPCSrv, c.Params("id"), agentID)
	conns, err := h.Repo.EBPF.ListConnections(c.UserContext(), agentID, limit)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	if conns == nil {
		conns = []repository.EBPFConnectionRow{}
	}
	return c.JSON(fiber.Map{
		"connections": conns,
		"count":       len(conns),
	})
}

// ── Bandwidth ───────────────────────────────────────────────────────────────

// ListBandwidth returns the latest bandwidth snapshot for an agent.
// ?limit= defaults to 100 and is capped at 1000.
//
//	GET /api/projects/:id/host/bandwidth?agent_id=<uuid>&limit=100
func (h *HostPolicyHandler) ListBandwidth(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	limit := boundedLimit(c, 100)
	requestLiveTelemetry(h.GRPCSrv, c.Params("id"), agentID)
	entries, err := h.Repo.EBPF.ListBandwidth(c.UserContext(), agentID, limit)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	if entries == nil {
		entries = []repository.EBPFBandwidthRow{}
	}
	return c.JSON(fiber.Map{
		"entries": entries,
		"count":   len(entries),
	})
}

// ── Config (proxied to agent — write operations) ────────────────────────────
// Config/Blocklist/Allowlist/Geo operations need to reach the agent.
// For now, these return the last known snapshot or a "not available" message.
// In a production setup, the server would forward commands to the agent
// via a reverse channel (e.g. agent long-polls for commands).

// GetConfig returns the eBPF firewall configuration from the desired state.
//
//	GET /api/ebpf/config?agent_id=<uuid>
func (h *HostPolicyHandler) GetConfig(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	if s.Config != nil {
		return c.JSON(s.Config)
	}
	// Fall back to status snapshot for backwards compatibility.
	payload, _, serr := h.Repo.EBPF.LatestStatus(c.UserContext(), agentID)
	if serr != nil {
		return c.JSON(fiber.Map{})
	}
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(payload, &wrapper); err == nil {
		if inner, ok := wrapper["ebpf"]; ok {
			var ebpfObj map[string]json.RawMessage
			if err := json.Unmarshal(inner, &ebpfObj); err == nil {
				if cfgData, ok := ebpfObj["config"]; ok {
					c.Set("Content-Type", "application/json")
					return c.Send(cfgData)
				}
			}
		}
	}
	return c.JSON(fiber.Map{})
}

// applyConfigUpdate puts a new firewall config into the stored state. The
// stored state is normalised first: one saved dormant (allow mode with geo
// off and an old acknowledgement, written before normalizeGeoState
// existed) must not re-enter allow mode when the new config turns geo back
// on; writeState normalises the result again.
func applyConfigUpdate(s *ebpfDesiredState, cfg hostpolicy.FullConfigAPI) {
	normalizeGeoState(s)
	s.Config = &cfg
}

// PutConfig updates the eBPF firewall config in the desired state and pushes it
// to the agent via gRPC.
//
//	PUT /api/ebpf/config
func (h *HostPolicyHandler) PutConfig(c *fiber.Ctx) error {
	agentID, projectID, err := h.resolveAgentAndProject(c)
	if err != nil {
		return err
	}
	var cfg hostpolicy.FullConfigAPI
	if err := json.Unmarshal(c.Body(), &cfg); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid config body", "code": "BAD_REQUEST"})
	}
	// The agent refuses the whole bundle over a value its maps cannot hold
	// (and port-scan thresholds above the dataplane limit never detected):
	// refuse it here, before it is stored.
	if err := hostpolicy.ValidateRateConfig(cfg.Rate); err != nil {
		return invalidInput(c, "INVALID_CONFIG", err)
	}
	if err := hostpolicy.ValidatePortScanConfig(cfg.PortScan); err != nil {
		return invalidInput(c, "INVALID_CONFIG", err)
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	wasAllow := s.GeoMode == hostpolicy.GeoModeAllow
	applyConfigUpdate(s, cfg)
	warnings, err := h.writeState(c.UserContext(), agentID, projectID, s)
	if err != nil {
		return desiredStateWriteError(c, err)
	}
	firewallUserID, _ := c.Locals("user_id").(string)
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: firewallUserID,
		Action: repository.AuditFirewallConfigUpdated, TargetType: "agent", TargetID: agentID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"config": cfg},
	})
	// Geo switched off while in allow mode: the mode went back to block
	// (normalizeGeoState), which is a geo change of its own.
	if wasAllow && s.GeoMode != hostpolicy.GeoModeAllow {
		_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
			ProjectID: projectID, ActorUserID: firewallUserID,
			Action: repository.AuditFirewallGeoUpdated, TargetType: "agent", TargetID: agentID,
			IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
			MetadataJSON: map[string]any{"mode": hostpolicy.GeoModeBlock, "previous_mode": hostpolicy.GeoModeAllow,
				"reason": "geo filtering disabled", "allow_acknowledged": false},
		})
	}
	return jsonWithWarnings(c, cfg, warnings)
}

// ── Blocklist ───────────────────────────────────────────────────────────────

// desiredListPage answers a desired-state IP list with one page of it:
// ?limit= (≤ 1000; omitted = up to 1000) and ?offset=. "count" is the number
// of entries in this response, "total" the number of unexpired entries.
func desiredListPage[T any](c *fiber.Ctx, items []T) error {
	page := parsePage(c, maxBlocklistLimit)
	out := pageOf(items, page)
	return c.JSON(fiber.Map{"entries": out, "count": len(out), "total": len(items), "limit": page.Limit, "offset": page.Offset})
}

// ListBlocklist returns one page of the blocklist from the desired state.
// Expired entries are hidden; expiry is enforced by the agent and read
// requests do not mutate desired state.
//
//	GET /api/projects/:id/host/blocklist?agent_id=&limit=&offset=
func (h *HostPolicyHandler) ListBlocklist(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	return desiredListPage(c, prunedBlocklist(s.Blocklist))
}

// AddBlocklist adds IP entries to the desired blocklist and pushes to agent.
//
//	POST /api/ebpf/blocklist
func (h *HostPolicyHandler) AddBlocklist(c *fiber.Ctx) error {
	agentID, projectID, err := h.resolveAgentAndProject(c)
	if err != nil {
		return err
	}
	var req struct {
		Entries []hostpolicy.IPEntry `json:"entries"`
	}
	if err := json.Unmarshal(c.Body(), &req); err != nil || len(req.Entries) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "entries required", "code": "BAD_REQUEST"})
	}
	for _, e := range req.Entries {
		if err := validateIPEntry(e.IP); err != nil {
			return invalidInput(c, "INVALID_IP", err)
		}
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	if err := addBlocklist(s, req.Entries, time.Now().UTC()); err != nil {
		return ipListError(c, "blocklist", err)
	}
	warnings, err := h.writeState(c.UserContext(), agentID, projectID, s)
	if err != nil {
		return desiredStateWriteError(c, err)
	}
	blAddUserID, _ := c.Locals("user_id").(string)
	addedIPs := make([]string, 0, len(req.Entries))
	for _, e := range req.Entries {
		addedIPs = append(addedIPs, e.IP)
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: blAddUserID,
		Action: repository.AuditFirewallBlocklistAdded, TargetType: "agent", TargetID: agentID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"ips": addedIPs},
	})
	return jsonWithWarnings(c, fiber.Map{"status": "ok", "count": len(s.Blocklist)}, warnings)
}

// DELETE /api/ebpf/blocklist
func (h *HostPolicyHandler) DeleteBlocklist(c *fiber.Ctx) error {
	agentID, projectID, err := h.resolveAgentAndProject(c)
	if err != nil {
		return err
	}
	var req struct {
		Entries []struct {
			IP string `json:"ip"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(c.Body(), &req); err != nil || len(req.Entries) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "entries required"})
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	removeBlocklist(s, entryIPs(req.Entries))
	warnings, err := h.writeState(c.UserContext(), agentID, projectID, s)
	if err != nil {
		return desiredStateWriteError(c, err)
	}
	blDelUserID, _ := c.Locals("user_id").(string)
	removedIPs := make([]string, 0, len(req.Entries))
	for _, e := range req.Entries {
		removedIPs = append(removedIPs, e.IP)
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: blDelUserID,
		Action: repository.AuditFirewallBlocklistRemoved, TargetType: "agent", TargetID: agentID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"ips": removedIPs},
	})
	return jsonWithWarnings(c, fiber.Map{"status": "ok", "count": len(s.Blocklist)}, warnings)
}

// ── Allowlist ───────────────────────────────────────────────────────────────

// ListAllowlist returns one page of the allowlist from the desired state
// (expired entries hidden; see desiredListPage).
//
//	GET /api/projects/:id/host/allowlist?agent_id=&limit=&offset=
func (h *HostPolicyHandler) ListAllowlist(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	projectID := c.Params("id")
	sshPorts := h.agentSSHPorts(c.UserContext(), projectID, agentID)
	entries := prunedAllowlist(s.Allowlist)
	views := make([]allowlistEntryView, 0, len(entries))
	for _, e := range entries {
		ports := e.Ports
		if ports == nil {
			ports = []hostpolicy.PortScope{}
		}
		views = append(views, allowlistEntryView{IP: e.IP, AddedAt: e.AddedAt, ExpiresAt: e.ExpiresAt, HitCount: e.HitCount,
			Ports: ports, LockoutEscape: hostpolicy.LockoutEscape(e, sshPorts)})
	}
	page := parsePage(c, maxBlocklistLimit)
	out := pageOf(views, page)
	return c.JSON(fiber.Map{"entries": out, "count": len(out), "total": len(views), "limit": page.Limit, "offset": page.Offset,
		"allowlist_ports_supported": h.agentHasFirewallFeature(c.UserContext(), projectID, agentID, hostpolicy.AllowlistFeaturePorts)})
}

// allowlistEntryView is an allowlist entry as GET returns it: ports always
// present ([] = every port and protocol) and lockout_escape computed with
// the host's SSH ports (ebpf.LockoutEscape: what the lockout guard counts
// as a management escape hatch).
type allowlistEntryView struct {
	IP            string                 `json:"ip"`
	AddedAt       time.Time              `json:"added_at"`
	ExpiresAt     *time.Time             `json:"expires_at,omitempty"`
	HitCount      uint32                 `json:"hit_count"`
	Ports         []hostpolicy.PortScope `json:"ports"`
	LockoutEscape bool                   `json:"lockout_escape"`
}

// allowlistIdentity is the identity of an allowlist entry: its canonical
// prefixes, so re-adding "10.0.0.1/24" replaces "10.0.0.0/24".
func allowlistIdentity(ip string) string {
	keys, err := hostpolicy.IPListKeys(ip)
	if err != nil || len(keys) == 0 {
		return strings.TrimSpace(ip)
	}
	return strings.Join(keys, ",")
}

// maxAllowlistAddEntries caps one allowlist add at the allowlist's capacity
// (10,000 prefixes): a larger request can never be stored, and it is refused
// before any entry is parsed.
const maxAllowlistAddEntries = 10000

// allowlistAddError is a refused allowlist add: the API code and the cause.
type allowlistAddError struct {
	code string
	err  error
}

// parseAllowlistAdd decodes and checks the body of POST …/host/allowlist:
// at least one entry, each a valid address, CIDR or range, its ports
// normalised (INVALID_PORTS, ALLOWLIST_PORTS_TOO_MANY) and never on a
// family-wide entry (ALLOWLIST_WILDCARD_SCOPED). scoped: some entry has
// ports.
func parseAllowlistAdd(body []byte) (entries []hostpolicy.IPEntry, scoped bool, perr *allowlistAddError) {
	var req struct {
		Entries []hostpolicy.IPEntry `json:"entries"`
	}
	if err := json.Unmarshal(body, &req); err != nil || len(req.Entries) == 0 {
		return nil, false, &allowlistAddError{code: "BAD_REQUEST", err: errors.New("entries required")}
	}
	if len(req.Entries) > maxAllowlistAddEntries {
		return nil, false, &allowlistAddError{code: "IP_LIST_FULL",
			err: fmt.Errorf("an allowlist add takes at most %d entries, the allowlist's capacity", maxAllowlistAddEntries)}
	}
	return checkAllowlistEntries(req.Entries)
}

// checkAllowlistEntries validates allowlist entries and normalises their
// ports in place (shared by the single-host add and the multi-host apply).
func checkAllowlistEntries(entries []hostpolicy.IPEntry) (_ []hostpolicy.IPEntry, scoped bool, perr *allowlistAddError) {
	for i, e := range entries {
		if err := validateIPEntry(e.IP); err != nil {
			return nil, false, &allowlistAddError{code: "INVALID_IP", err: err}
		}
		ports, err := hostpolicy.NormalizePortScopes(e.Ports)
		if err != nil {
			code, ok := hostpolicy.FirewallErrorCode(err)
			if !ok {
				code = "INVALID_PORTS"
			}
			return nil, false, &allowlistAddError{code: code, err: err}
		}
		if len(ports) > 0 && isFamilyWideEntry(e.IP) {
			return nil, false, &allowlistAddError{code: "ALLOWLIST_WILDCARD_SCOPED", err: hostpolicy.ErrAllowlistWildcardScoped}
		}
		entries[i].Ports = ports
		scoped = scoped || len(ports) > 0
	}
	return entries, scoped, nil
}

// isFamilyWideEntry: the entry lands on 0.0.0.0/0 or ::/0 (any spelling).
func isFamilyWideEntry(ip string) bool {
	prefixes, err := hostpolicy.IPListPrefixes(ip)
	if err != nil {
		return false
	}
	for _, p := range prefixes {
		if p.Bits() == 0 {
			return true
		}
	}
	return false
}

// AddAllowlist adds IP entries to the desired allowlist and pushes to agent.
// An entry may carry ports (empty = every port and protocol);
// re-adding a prefix replaces its ports and TTL. Scoped entries need a host
// that reported "allowlist_ports" (409 ALLOWLIST_PORTS_UNSUPPORTED).
//
//	POST /api/projects/:id/host/allowlist
func (h *HostPolicyHandler) AddAllowlist(c *fiber.Ctx) error {
	agentID, projectID, err := h.resolveAgentAndProject(c)
	if err != nil {
		return err
	}
	entries, scoped, perr := parseAllowlistAdd(c.Body())
	if perr != nil {
		if perr.code == "BAD_REQUEST" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "entries required", "code": "BAD_REQUEST"})
		}
		return invalidInput(c, perr.code, perr.err)
	}
	// A host whose objects cannot match scopes would leave the entry out
	// (fail closed); refuse it here so the dashboard says so at once.
	if scoped && !h.agentHasFirewallFeature(c.UserContext(), projectID, agentID, hostpolicy.AllowlistFeaturePorts) {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "The host agent has not reported support for port-scoped allowlist entries. Update the host agent together with its eBPF objects, or add the entry for every port.",
			"code":  "ALLOWLIST_PORTS_UNSUPPORTED",
		})
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	auditEntries, err := addAllowlist(s, entries, time.Now().UTC())
	if err != nil {
		return ipListError(c, "allowlist", err)
	}
	warnings, err := h.writeState(c.UserContext(), agentID, projectID, s)
	if err != nil {
		return desiredStateWriteError(c, err)
	}
	alAddUserID, _ := c.Locals("user_id").(string)
	addedAlIPs := make([]string, 0, len(entries))
	for _, e := range entries {
		addedAlIPs = append(addedAlIPs, e.IP)
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: alAddUserID,
		Action: repository.AuditFirewallAllowlistAdded, TargetType: "agent", TargetID: agentID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"ips": addedAlIPs, "entries": auditEntries},
	})
	return jsonWithWarnings(c, fiber.Map{"status": "ok", "count": len(s.Allowlist)}, warnings)
}

// upsertAllowlist adds entries to an allowlist by identity (the canonical
// prefixes): a re-added prefix replaces its stored entry in place,
// ports and TTL included — and any other spelling of it is dropped, so the
// prefix keeps one set of ports. It returns the new list and one audit
// record per added entry: {ip, ports, expires_at, previous_ports} (previous
// ports null for a new prefix, [] for one that allowed every port). Each
// identity is computed once, so an add is linear in the list and the request
// (it used to rescan the list per added entry).
func upsertAllowlist(list []hostpolicy.AllowlistEntry, add []hostpolicy.IPEntry, now time.Time) ([]hostpolicy.AllowlistEntry, []map[string]any) {
	ids := make([]string, len(list), len(list)+len(add))
	first := make(map[string]int, len(list)+len(add)) // identity -> index of its kept entry
	for i, e := range list {
		ids[i] = allowlistIdentity(e.IP)
		if _, seen := first[ids[i]]; !seen {
			first[ids[i]] = i
		}
	}
	touched := make(map[string]bool, len(add))
	audit := make([]map[string]any, 0, len(add))
	for _, e := range add {
		entry := hostpolicy.AllowlistEntry{IP: strings.TrimSpace(e.IP), AddedAt: now, Ports: e.Ports}
		if e.TTLMs > 0 {
			exp := now.Add(time.Duration(e.TTLMs) * time.Millisecond)
			entry.ExpiresAt = &exp
		}
		rec := map[string]any{"ip": entry.IP, "ports": auditPorts(entry.Ports), "expires_at": entry.ExpiresAt, "previous_ports": nil}
		id := allowlistIdentity(entry.IP)
		touched[id] = true
		if idx, ok := first[id]; ok {
			rec["previous_ports"] = auditPorts(list[idx].Ports)
			list[idx] = entry
		} else {
			first[id] = len(list)
			list = append(list, entry)
			ids = append(ids, id)
		}
		audit = append(audit, rec)
	}
	out := make([]hostpolicy.AllowlistEntry, 0, len(list))
	for i, e := range list {
		if touched[ids[i]] && first[ids[i]] != i {
			continue // another spelling of a re-added prefix
		}
		out = append(out, e)
	}
	return out, audit
}

// geoAllowAllowlistRemovedWarning: an allowlist removal under geo allow mode.
var geoAllowAllowlistRemovedWarning = hostpolicy.FirewallWarning{
	Code: WarnGeoAllowAllowlistRemoved,
	Message: "Geo allow mode is active: the removed addresses can no longer reach the host from outside the allowed countries, " +
		"and connections they opened after allow mode went live are cut. Re-add your management address if you administer the host from abroad.",
}

// entryIPs lists the ip of each {ip} body entry.
func entryIPs(entries []struct {
	IP string `json:"ip"`
}) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.IP)
	}
	return out
}

// auditPorts spells an entry's ports for the audit log: [] = every port.
func auditPorts(ports []hostpolicy.PortScope) []string {
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		out = append(out, p.String())
	}
	return out
}

// DeleteAllowlist removes IP entries from the desired allowlist and pushes to agent.
//
//	DELETE /api/ebpf/allowlist
func (h *HostPolicyHandler) DeleteAllowlist(c *fiber.Ctx) error {
	agentID, projectID, err := h.resolveAgentAndProject(c)
	if err != nil {
		return err
	}
	var req struct {
		Entries []struct {
			IP string `json:"ip"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(c.Body(), &req); err != nil || len(req.Entries) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "entries required"})
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	removeAllowlist(s, entryIPs(req.Entries))
	warnings, err := h.writeState(c.UserContext(), agentID, projectID, s)
	if err != nil {
		return desiredStateWriteError(c, err)
	}
	// Removing an allowlist entry needs no acknowledgement, but under geo
	// allow mode it can take away the operator's own way in.
	if geoAllowActive(s) {
		warnings = append(warnings, geoAllowAllowlistRemovedWarning)
	}
	alDelUserID, _ := c.Locals("user_id").(string)
	removedAlIPs := make([]string, 0, len(req.Entries))
	for _, e := range req.Entries {
		removedAlIPs = append(removedAlIPs, e.IP)
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: alDelUserID,
		Action: repository.AuditFirewallAllowlistRemoved, TargetType: "agent", TargetID: agentID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"ips": removedAlIPs},
	})
	return jsonWithWarnings(c, fiber.Map{"status": "ok", "count": len(s.Allowlist)}, warnings)
}

// ── Geo-blocking ────────────────────────────────────────────────────────────

// ListGeoBlocked returns the geo-blocked countries from the desired state.
//
//	GET /api/ebpf/geo/blocked
func (h *HostPolicyHandler) ListGeoBlocked(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	if s.GeoBlocked == nil {
		s.GeoBlocked = []hostpolicy.CountryEntry{}
	}
	mode, ok := hostpolicy.NormalizeGeoMode(s.GeoMode)
	if !ok {
		mode = hostpolicy.GeoModeBlock
	}
	allowed := s.GeoAllowed
	if allowed == nil {
		allowed = []string{}
	}
	return c.JSON(fiber.Map{
		"countries": s.GeoBlocked, "count": len(s.GeoBlocked),
		"mode": mode, "allowed_countries": allowed,
		"allow_acknowledged": mode == hostpolicy.GeoModeAllow && s.GeoAllowAcknowledged,
		"allow_supported":    h.agentHasFirewallFeature(c.UserContext(), c.Params("id"), agentID, hostpolicy.GeoFeatureAllow),
	})
}

// geoUpdateRequest is the body of PUT /geo/blocked. Every field is
// optional: countries changes the block list (blocked: true adds, false
// removes), allowed_countries the allow list (allowed: true adds, false
// removes), mode switches between "block" and "allow". allow_acknowledged
// is the confirm dialog's answer; it is required when the result is allow
// mode and the request switches to it or removes an allowed country.
type geoUpdateRequest struct {
	Countries         []hostpolicy.CountryEntry        `json:"countries"`
	Mode              *string                          `json:"mode"`
	AllowedCountries  []hostpolicy.AllowedCountryEntry `json:"allowed_countries"`
	AllowAcknowledged bool                             `json:"allow_acknowledged"`
}

// geoChange summarises what applyGeoUpdate did.
type geoChange struct {
	prevMode, mode  string
	switchedToAllow bool // allow mode goes from inactive to active
	listChanged     bool // the active mode's country list changed
}

// geoAllowActive: allow mode is in force (geo filtering on). Like the agent,
// geo counts as on without a config.
func geoAllowActive(s *ebpfDesiredState) bool {
	return s.GeoMode == hostpolicy.GeoModeAllow && (s.Config == nil || s.Config.Global.EnableGeoblock)
}

// normalizeGeoState keeps allow mode from lying dormant:
// geo filtering switched off while in allow mode returns the mode to block
// and drops the acknowledgement, so turning geo back on (the Settings
// toggle, PUT /host/config) re-enters block mode, and allow mode comes back
// only through the geo endpoint — fresh acknowledgement, agent support
// check, requester warning and a firewall.geo_updated audit entry. Every
// mode other than allow drops the acknowledgement too.
func normalizeGeoState(s *ebpfDesiredState) {
	if s.GeoMode == hostpolicy.GeoModeAllow && s.Config != nil && !s.Config.Global.EnableGeoblock {
		s.GeoMode = hostpolicy.GeoModeBlock
	}
	if s.GeoMode != hostpolicy.GeoModeAllow {
		s.GeoAllowAcknowledged = false
	}
}

// applyGeoUpdate merges a geo request into the desired state. Country codes
// are normalised to upper case and the lists sorted; an invalid code or mode
// is refused (hostpolicy.ErrGeoCountryInvalid / ErrGeoModeInvalid). Switching
// to allow mode, or removing an allowed country while in it, takes the
// request's acknowledgement (the lockout guard then refuses a missing one);
// adding allowed countries only widens access and keeps the stored one.
// Block mode clears it. Geo filtering is switched on with allow mode, and
// with a non-empty block list as before. Allow mode stored but inactive
// (geo off) counts as a switch, never as a silent re-entry.
func applyGeoUpdate(s *ebpfDesiredState, req geoUpdateRequest) (geoChange, error) {
	prev, ok := hostpolicy.NormalizeGeoMode(s.GeoMode)
	if !ok {
		prev = hostpolicy.GeoModeBlock
	}
	wasActive := prev == hostpolicy.GeoModeAllow && (s.Config == nil || s.Config.Global.EnableGeoblock)
	ch := geoChange{prevMode: prev, mode: prev}
	if req.Mode != nil {
		mode, ok := hostpolicy.NormalizeGeoMode(*req.Mode)
		if !ok || strings.TrimSpace(*req.Mode) == "" {
			return ch, fmt.Errorf("%w (got %q)", hostpolicy.ErrGeoModeInvalid, clipGeo(*req.Mode))
		}
		ch.mode = mode
	}

	blocked := make(map[string]bool, len(s.GeoBlocked))
	for _, e := range s.GeoBlocked {
		code := e.Code
		if n, ok := hostpolicy.NormalizeCountryCode(code); ok {
			code = n
		}
		blocked[code] = e.Blocked
	}
	blockedChanged := false
	for _, e := range req.Countries {
		code, ok := hostpolicy.NormalizeCountryCode(e.Code)
		if !ok {
			return ch, fmt.Errorf("%w (got %q)", hostpolicy.ErrGeoCountryInvalid, clipGeo(e.Code))
		}
		if e.Blocked {
			blockedChanged = blockedChanged || !blocked[code]
			blocked[code] = true
		} else if _, had := blocked[code]; had {
			blockedChanged = true
			delete(blocked, code)
		}
	}
	merged := make([]hostpolicy.CountryEntry, 0, len(blocked))
	for code, b := range blocked {
		merged = append(merged, hostpolicy.CountryEntry{Code: code, Blocked: b})
	}
	slices.SortFunc(merged, func(a, b hostpolicy.CountryEntry) int { return strings.Compare(a.Code, b.Code) })
	s.GeoBlocked = merged

	allowed := make(map[string]bool, len(s.GeoAllowed))
	for _, code := range s.GeoAllowed {
		if n, ok := hostpolicy.NormalizeCountryCode(code); ok {
			code = n
		}
		allowed[code] = true
	}
	removedAllowed, addedAllowed := false, false
	for _, e := range req.AllowedCountries {
		code, ok := hostpolicy.NormalizeCountryCode(e.Code)
		if !ok {
			return ch, fmt.Errorf("%w (got %q)", hostpolicy.ErrGeoCountryInvalid, clipGeo(e.Code))
		}
		if e.Allowed {
			addedAllowed = addedAllowed || !allowed[code]
			allowed[code] = true
		} else if allowed[code] {
			delete(allowed, code)
			removedAllowed = true
		}
	}
	s.GeoAllowed = make([]string, 0, len(allowed))
	for code := range allowed {
		s.GeoAllowed = append(s.GeoAllowed, code)
	}
	slices.Sort(s.GeoAllowed)

	s.GeoMode = ch.mode
	if ch.mode == hostpolicy.GeoModeAllow {
		ch.switchedToAllow = !wasActive
		ch.listChanged = ch.switchedToAllow || removedAllowed || addedAllowed
		if ch.switchedToAllow || removedAllowed {
			s.GeoAllowAcknowledged = req.AllowAcknowledged
		}
		if s.Config == nil {
			def := hostpolicy.DefaultFullConfigAPI()
			s.Config = &def
		}
		s.Config.Global.EnableGeoblock = true
	} else {
		ch.listChanged = prev != ch.mode || blockedChanged
		s.GeoAllowAcknowledged = false
		if s.Config != nil && len(s.GeoBlocked) > 0 {
			s.Config.Global.EnableGeoblock = true
		}
	}
	return ch, nil
}

// GeoRangeSource lists the GeoIP ranges of countries: the control plane's
// own country database (*geo.MaxMindLookup), used to refuse a geo list the
// host's tries cannot hold before it is stored.
type GeoRangeSource interface {
	ForEachCountryCIDR(codes []string, fn func(*net.IPNet)) error
}

// geoCapacityCheck refuses a geo list that would not fit the host's geo
// tries (GEO_RANGES_EXCEED_CAPACITY), or an allow list without a single
// range in the data (GEO_ALLOW_NO_RANGES), with the control plane's GeoIP
// database. Without one — or when it cannot be read — the agent's own
// check (planGeo) decides; it degrades geo only.
func (h *HostPolicyHandler) geoCapacityCheck(s *ebpfDesiredState) error {
	if h.GeoRanges == nil {
		return nil
	}
	codes := s.GeoAllowed
	if s.GeoMode != hostpolicy.GeoModeAllow {
		codes = nil
		for _, e := range s.GeoBlocked {
			if e.Blocked {
				codes = append(codes, e.Code)
			}
		}
	}
	if len(codes) == 0 {
		return nil
	}
	var prefixes []netip.Prefix
	if err := h.GeoRanges.ForEachCountryCIDR(codes, func(n *net.IPNet) {
		if p, ok := hostpolicy.GeoPrefixFromIPNet(n); ok {
			prefixes = append(prefixes, p)
		}
	}); err != nil {
		slog.Warn("geo_capacity_check_skipped", "err", err)
		return nil
	}
	if s.GeoMode == hostpolicy.GeoModeAllow && len(prefixes) == 0 {
		return hostpolicy.ErrGeoAllowNoRanges
	}
	_, _, err := hostpolicy.GeoRangesFit(prefixes)
	return err
}

// clipGeo keeps echoed client input short in an error message.
func clipGeo(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}

// agentHasFirewallFeature reports whether the host agent listed feature in
// host_info.firewall_features; false when unknown or unreadable.
func (h *HostPolicyHandler) agentHasFirewallFeature(ctx context.Context, projectID, agentID, feature string) bool {
	return slices.Contains(h.agentFirewallFeatures(ctx, projectID, agentID), feature)
}

// agentFirewallFeatures is host_info.firewall_features of the host agent;
// nil when unknown or unreadable.
func (h *HostPolicyHandler) agentFirewallFeatures(ctx context.Context, projectID, agentID string) []string {
	if h.Repo == nil || h.Repo.EBPF == nil {
		return nil
	}
	features, err := h.Repo.EBPF.GetAgentFirewallFeatures(ctx, projectID, agentID)
	if err != nil {
		slog.Warn("firewall_features_unavailable", "agent_id", agentID, "err", err)
		return nil
	}
	return features
}

// UpdateGeoBlocked changes the geo countries and mode and pushes to agent.
//
//	PUT /api/projects/:id/host/geo/blocked
func (h *HostPolicyHandler) UpdateGeoBlocked(c *fiber.Ctx) error {
	agentID, projectID, err := h.resolveAgentAndProject(c)
	if err != nil {
		return err
	}
	var req geoUpdateRequest
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "BAD_REQUEST"})
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	change, err := applyGeoUpdate(s, req)
	if err != nil {
		return desiredStateWriteError(c, err)
	}
	// A host agent older than allow mode would ignore the allowed countries
	// (fail open) and report the policy as applied; one without a GeoIP
	// dataset would refuse it. Only switch hosts that reported support.
	if change.switchedToAllow && !h.agentHasFirewallFeature(c.UserContext(), projectID, agentID, hostpolicy.GeoFeatureAllow) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "The host agent has not reported geo allow mode support. Update the host agent and its eBPF objects together, and install the GeoIP country database (security data geoip-country).",
			"code":  "GEO_ALLOW_UNSUPPORTED",
		})
	}
	if change.listChanged {
		if err := h.geoCapacityCheck(s); err != nil {
			return desiredStateWriteError(c, err)
		}
	}

	warnings, err := h.writeState(c.UserContext(), agentID, projectID, s)
	if err != nil {
		return desiredStateWriteError(c, err)
	}
	if w, ok := h.geoRequesterOutside(c.IP(), s); ok {
		warnings = append(warnings, w)
	}
	geoUserID, _ := c.Locals("user_id").(string)
	codes := make([]string, 0, len(req.Countries))
	for _, c2 := range req.Countries {
		codes = append(codes, c2.Code)
	}
	allowedCodes := make([]string, 0, len(req.AllowedCountries))
	for _, c2 := range req.AllowedCountries {
		allowedCodes = append(allowedCodes, c2.Code)
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: geoUserID,
		Action: repository.AuditFirewallGeoUpdated, TargetType: "agent", TargetID: agentID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{
			"countries": codes, "allowed_countries": allowedCodes,
			"mode": change.mode, "previous_mode": change.prevMode,
			"allow_acknowledged": s.GeoAllowAcknowledged,
		},
	})
	return jsonWithWarnings(c, fiber.Map{
		"status": "ok", "count": len(s.GeoBlocked),
		"mode": change.mode, "allowed_count": len(s.GeoAllowed),
	}, warnings)
}

// WarnGeoAllowRequesterOutside: the address the change came from resolves
// to a country outside the allow list (best effort: the control plane sees
// the dashboard client, which is not always the SSH client).
const WarnGeoAllowRequesterOutside = "GEO_ALLOW_REQUESTER_OUTSIDE"

// WarnGeoAllowAllowlistRemoved: allowlist entries were removed while geo
// allow mode is active (no acknowledgement is asked for that).
const WarnGeoAllowAllowlistRemoved = "GEO_ALLOW_ALLOWLIST_REMOVED"

// geoRequesterOutside warns when allow mode is active and the requesting
// address resolves to a country that is not allowed.
func (h *HostPolicyHandler) geoRequesterOutside(ip string, s *ebpfDesiredState) (hostpolicy.FirewallWarning, bool) {
	if h.GeoEnricher == nil || s.GeoMode != hostpolicy.GeoModeAllow || s.Config == nil || !s.Config.Global.EnableGeoblock {
		return hostpolicy.FirewallWarning{}, false
	}
	_, iso, _, _, _ := h.GeoEnricher.Enrich(ip)
	iso, ok := hostpolicy.NormalizeCountryCode(iso)
	if !ok || slices.Contains(s.GeoAllowed, iso) {
		return hostpolicy.FirewallWarning{}, false
	}
	return hostpolicy.FirewallWarning{
		Code: WarnGeoAllowRequesterOutside,
		Message: fmt.Sprintf("This change came from %s, which the GeoIP data places in %s, outside the allowed countries. "+
			"If you administer the host from there, add the address to the allowlist.", ip, iso),
	}, true
}

// ── Trace endpoints ─────────────────────────────────────────────────────────

// GetTraceStatus returns the latest trace status from status snapshot.
//
//	GET /api/ebpf/trace/status
func (h *HostPolicyHandler) GetTraceStatus(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	requestLiveStatus(h.GRPCSrv, c.Params("id"), agentID)

	// Compute agent liveness (same window as GetStatus).
	const agentLivenessWindow = 90 * time.Second
	agentOnline := false
	agent, agentErr := h.Repo.EBPF.GetAgentByID(c.UserContext(), agentID)
	if agentErr == nil && agent != nil && agent.LastSeen != nil {
		agentOnline = time.Since(*agent.LastSeen) <= agentLivenessWindow
	}
	if !agentOnline {
		if hostLastSeen, err := h.Repo.Host.GetAgentHostLastSeen(c.UserContext(), agentID); err == nil && hostLastSeen != nil {
			if time.Since(*hostLastSeen) <= agentLivenessWindow {
				agentOnline = true
			}
		}
	}

	payload, _, err := h.Repo.EBPF.LatestStatus(c.UserContext(), agentID)
	if err != nil {
		resp := fiber.Map{"running": false, "agent_online": agentOnline, "never_reported": true}
		if agentErr == nil && agent != nil {
			resp["agent_id"] = agent.ID
			resp["agent_name"] = agent.Name
			if agent.LastSeen != nil {
				resp["agent_last_seen"] = agent.LastSeen
			}
		}
		return c.JSON(resp)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(payload, &m); err != nil {
		return c.JSON(fiber.Map{"running": false, "agent_online": agentOnline})
	}
	if traceRaw, ok := m["trace"]; ok {
		// Inject agent_online so the UI can render liveness without a separate call.
		var traceMap map[string]interface{}
		if json.Unmarshal(traceRaw, &traceMap) == nil {
			traceMap["agent_online"] = agentOnline
			if reader, ok := h.GRPCSrv.(interface {
				HostBundleStatus(string, string) map[string]agentserver.HostBundleApplyStatus
			}); ok && agent != nil {
				traceMap["bundle_status"] = reader.HostBundleStatus(agentID, agent.ProjectID)
				traceMap["ingestion"] = h.Repo.EBPF.IngestionStatus(agentID)
			}
			if agentErr == nil && agent != nil && agent.LastSeen != nil {
				traceMap["agent_last_seen"] = agent.LastSeen
			}
			return c.JSON(traceMap)
		}
	}
	return c.JSON(fiber.Map{"running": false, "agent_online": agentOnline})
}

// GetTraceEvents returns recent trace events. ?limit= defaults to 500 and is
// capped at 1000.
//
//	GET /api/projects/:id/host/trace/events?agent_id=<uuid>&limit=500
func (h *HostPolicyHandler) GetTraceEvents(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	limit := boundedLimit(c, 500)
	sinceMinutes, _ := strconv.Atoi(c.Query("since_minutes", "0"))
	minSeverityStr := strings.ToLower(c.Query("min_severity", ""))
	minSeverity := severityNameToInt(minSeverityStr)

	var events []repository.TraceEventRow
	if sinceMinutes > 0 {
		since := time.Now().Add(-time.Duration(sinceMinutes) * time.Minute)
		// Pass minSeverity so DB filters in-DB rather than over-fetching.
		events, err = h.Repo.EBPF.RecentTraceEventsSince(c.UserContext(), agentID, since, limit, minSeverity)
	} else {
		// No time window — fetch more rows so in-memory severity filter has candidates.
		fetchLimit := limit
		if minSeverity > 0 {
			fetchLimit = limit * 10
			if fetchLimit > 5000 {
				fetchLimit = 5000
			}
		}
		events, err = h.Repo.EBPF.RecentTraceEvents(c.UserContext(), agentID, fetchLimit)
	}
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	if events == nil {
		events = []repository.TraceEventRow{}
	}

	// For non-sinceMinutes path only: apply in-memory severity filter and cap.
	if sinceMinutes == 0 && minSeverity > 0 {
		filtered := events[:0]
		for _, e := range events {
			if e.Severity >= minSeverity {
				filtered = append(filtered, e)
				if len(filtered) >= limit {
					break
				}
			}
		}
		events = filtered
	} else if len(events) > limit {
		events = events[:limit]
	}

	return c.JSON(events)
}

// GetTraceEventsByCategory returns trace events filtered by category.
// ?limit= defaults to 500 and is capped at 1000.
//
//	GET /api/projects/:id/host/trace/events/:category?agent_id=<uuid>&limit=500
func (h *HostPolicyHandler) GetTraceEventsByCategory(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	category := c.Params("category")
	limit := boundedLimit(c, 500)
	events, err := h.Repo.EBPF.RecentTraceEventsByCategory(c.UserContext(), agentID, category, limit)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	if events == nil {
		events = []repository.TraceEventRow{}
	}
	return c.JSON(events)
}

// GetTraceStats returns latest trace stats.
//
//	GET /api/ebpf/trace/stats?agent_id=<uuid>
func (h *HostPolicyHandler) GetTraceStats(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	requestLiveStatus(h.GRPCSrv, c.Params("id"), agentID)
	payload, _, err := h.Repo.EBPF.LatestTraceStats(c.UserContext(), agentID)
	if err != nil {
		return c.JSON(fiber.Map{})
	}
	return sendStoredJSONObject(c, payload)
}

// sendStoredJSONObject answers a JSON object an agent reported and the
// control plane stored as is. An agent that never reported has no row value
// (NULL, a nil payload without an error), which used to go out as an empty
// body with a JSON content type; it and a stored JSON null answer {}.
func sendStoredJSONObject(c *fiber.Ctx, payload []byte) error {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return c.JSON(fiber.Map{})
	}
	c.Set("Content-Type", "application/json")
	return c.Send(payload)
}

// GetTraceConfig returns the trace config from the desired state.
// Falls back to sensible defaults if never configured.
//
//	GET /api/ebpf/trace/config
func (h *HostPolicyHandler) GetTraceConfig(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	if s.TraceConfig != nil {
		return c.JSON(s.TraceConfig)
	}
	return c.JSON(fiber.Map{
		"enabled":      true,
		"filter_self":  true,
		"min_severity": "info",
		"event_types":  []string{},
	})
}

// PutTraceConfig updates the trace config in the desired state and pushes to agent.
//
//	PUT /api/ebpf/trace/config
func (h *HostPolicyHandler) PutTraceConfig(c *fiber.Ctx) error {
	agentID, projectID, err := h.resolveAgentAndProject(c)
	if err != nil {
		return err
	}
	var cfg hostpolicy.TraceConfigAPI
	if err := json.Unmarshal(c.Body(), &cfg); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid trace config body", "code": "BAD_REQUEST"})
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	if err := hostpolicy.ValidateTraceConfig(cfg); err != nil {
		return invalidInput(c, "BAD_REQUEST", err)
	}
	s.TraceConfig = &cfg
	if _, err := h.writeState(c.UserContext(), agentID, projectID, s); err != nil {
		return desiredStateWriteError(c, err)
	}
	tcUserID, _ := c.Locals("user_id").(string)
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: tcUserID,
		Action: repository.AuditTraceConfigUpdated, TargetType: "agent", TargetID: agentID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"config": cfg},
	})
	return c.JSON(cfg)
}

// ── Enforcement endpoints ───────────────────────────────────────────────────

// GetEnforcementLog returns recent enforcement log entries. ?limit= defaults
// to 500 and is capped at 1000.
//
//	GET /api/projects/:id/host/trace/enforcement?agent_id=<uuid>&limit=500
func (h *HostPolicyHandler) GetEnforcementLog(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	limit := boundedLimit(c, 500)
	sinceMinutes, _ := strconv.Atoi(c.Query("since_minutes", "0"))

	var entries []repository.EnforcementLogRow
	if sinceMinutes > 0 {
		since := time.Now().Add(-time.Duration(sinceMinutes) * time.Minute)
		entries, err = h.Repo.EBPF.RecentEnforcementLogSince(c.UserContext(), agentID, since, limit)
	} else {
		entries, err = h.Repo.EBPF.RecentEnforcementLog(c.UserContext(), agentID, limit)
	}
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	if entries == nil {
		entries = []repository.EnforcementLogRow{}
	}
	return c.JSON(entries)
}

// ── Trace Types ─────────────────────────────────────────────────────────────

// GetTraceTypes returns the static list of all trace event types.
//
//	GET /api/ebpf/trace/types
func (h *HostPolicyHandler) GetTraceTypes(c *fiber.Ctx) error {
	type eventTypeInfo struct {
		ID          uint32 `json:"id"`
		Name        string `json:"name"`
		Category    string `json:"category"`
		Description string `json:"description"`
	}
	var types []eventTypeInfo
	for id := uint32(1); id <= hostpolicy.TraceEventMax; id++ {
		info := hostpolicy.TraceEventTypes[id]
		var catParts []string
		if info.Category&hostpolicy.CatProcess != 0 {
			catParts = append(catParts, "process")
		}
		if info.Category&hostpolicy.CatFile != 0 {
			catParts = append(catParts, "file")
		}
		if info.Category&hostpolicy.CatNetwork != 0 {
			catParts = append(catParts, "network")
		}
		if info.Category&hostpolicy.CatSecurity != 0 {
			catParts = append(catParts, "security")
		}
		if info.Category&hostpolicy.CatContainer != 0 {
			catParts = append(catParts, "container")
		}
		cat := "unknown"
		if len(catParts) > 0 {
			cat = catParts[0]
			for i := 1; i < len(catParts); i++ {
				cat += "," + catParts[i]
			}
		}
		types = append(types, eventTypeInfo{
			ID:          id,
			Name:        info.Name,
			Category:    cat,
			Description: info.Description,
		})
	}
	return c.JSON(types)
}

// ── Enforcement Policies (persisted in DB + mirrored to agent) ──────────────
//
// The agent owns the live PolicyEngine in memory; the server is the source
// of truth in ebpf_trace_policies and pushes every change to the agent over
// gRPC (pushPoliciesAfterChange). These handlers read and write only the
// stored rows: agents have had no HTTP callback since migration 000031
// dropped agents.callback_url, so the old "forward to the agent when
// reachable" branches never ran and were removed.

// ListPolicies returns the stored policies of the agent.
//
//	GET /api/ebpf/trace/policies
func (h *HostPolicyHandler) ListPolicies(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}

	// The stored copies; agents get changes over gRPC (pushPoliciesAfterChange)
	// and report hit counts with their telemetry.
	rows, err := h.Repo.EBPF.ListTracePoliciesByAgent(c.UserContext(), agentID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	out := make([]hostpolicy.EnforcementPolicy, 0, len(rows))
	for i := range rows {
		out = append(out, *rowToPolicy(&rows[i]))
	}
	return c.JSON(out)
}

// CreatePolicy stores a new policy (201 with the stored policy) and pushes
// the agent's policies over gRPC.
//
//	POST /api/ebpf/trace/policies
func (h *HostPolicyHandler) CreatePolicy(c *fiber.Ctx) error {
	agentID, projectID, err := h.resolveAgentAndProject(c)
	if err != nil {
		return err
	}
	var requestedPolicy hostpolicy.EnforcementPolicy
	if err := json.Unmarshal(c.Body(), &requestedPolicy); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid policy body", "code": "BAD_REQUEST"})
	}
	if err := hostpolicy.ValidateEnforcementPolicy(requestedPolicy); err != nil {
		return invalidInput(c, "BAD_REQUEST", err)
	}
	createPolicyUserID, _ := c.Locals("user_id").(string)
	pol := requestedPolicy
	// Normalise kernel enforcement flags: when user asks for kernel enforcement,
	// set both KernelEnforce and KernelEnforceRequested so the agent receives
	// the correct intent and can apply kernel-side rules.
	if pol.KernelEnforce {
		pol.KernelEnforceRequested = true
	}
	// A new policy compares process names as whole words unless the request
	// chose a mode.
	hostpolicy.DefaultCommMatchMode(&pol, "")
	// Assign a synthetic policy_id (max existing + 1 for this agent),
	// allocated and inserted atomically: a concurrent create never gets the
	// same id or overwrites another policy (migration 000101).
	pol.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	pol.UpdatedAt = pol.CreatedAt
	_, nextID, perr := h.Repo.EBPF.CreateTracePolicy(c.UserContext(), policyToRow(agentID, &pol))
	if perr != nil {
		log.Printf("[trace policy] create failed agent=%s: %v", agentID, perr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to save policy"})
	}
	pol.ID = clampUint32(nextID)
	log.Printf("[trace policy] policy %q saved (id=%d)", pol.Name, pol.ID)
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: createPolicyUserID,
		Action: repository.AuditTracePolicyCreated, TargetType: "trace_policy", TargetID: agentID, TargetName: pol.Name,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"policy_id": pol.ID, "policy_name": pol.Name, "enabled": pol.Enabled, "kernel_enforce": pol.KernelEnforce},
	})
	h.pushPoliciesAfterChange(agentID)
	return c.Status(http.StatusCreated).JSON(pol)
}

// GetPolicy returns one stored policy.
//
//	GET /api/ebpf/trace/policies/:id
func (h *HostPolicyHandler) GetPolicy(c *fiber.Ctx) error {
	policyID := c.Params("policyId")
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	pid, ok := parsePolicyID(policyID)
	if !ok {
		return invalidPolicyID(c)
	}
	rows, rerr := h.Repo.EBPF.ListTracePoliciesByAgent(c.UserContext(), agentID)
	if rerr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	for i := range rows {
		if rows[i].PolicyID != nil && *rows[i].PolicyID == pid {
			return c.JSON(rowToPolicy(&rows[i]))
		}
	}
	return policyNotFound(c)
}

// UpdatePolicy updates a stored policy, answers the stored row and pushes
// the agent's policies over gRPC.
//
//	PUT /api/projects/:id/ebpf/trace/policies/:policyId
func (h *HostPolicyHandler) UpdatePolicy(c *fiber.Ctx) error {
	policyID := c.Params("policyId")
	agentID, projectID, err := h.resolveAgentAndProject(c)
	if err != nil {
		return err
	}
	pid, ok := parsePolicyID(policyID)
	if !ok {
		return invalidPolicyID(c)
	}
	var requestedPolicy hostpolicy.EnforcementPolicy
	if err := json.Unmarshal(c.Body(), &requestedPolicy); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid policy body", "code": "BAD_REQUEST"})
	}
	if err := hostpolicy.ValidateEnforcementPolicy(requestedPolicy); err != nil {
		return invalidInput(c, "BAD_REQUEST", err)
	}
	updatePolicyUserID, _ := c.Locals("user_id").(string)
	pol := requestedPolicy
	// The upsert below inserts when no row matches, so an update of a
	// policy the agent never had must stop here rather than create it.
	rows, lerr := h.Repo.EBPF.ListTracePoliciesByAgent(c.UserContext(), agentID)
	if lerr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update policy"})
	}
	if !hasStoredPolicy(rows, pid) {
		return policyNotFound(c)
	}
	pol.ID = clampUint32(pid)
	pol.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	// An update without match_comm_mode keeps the stored mode: a
	// client that predates the field must not silently re-scope the policy.
	if pol.MatchCommMode == "" {
		hostpolicy.DefaultCommMatchMode(&pol, existingCommMatchMode(rows, pid))
	}
	row := policyToRow(agentID, &pol)
	if _, perr := h.Repo.EBPF.UpsertTracePolicy(c.UserContext(), row); perr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update policy"})
	}
	log.Printf("[trace policy] policy %d updated", pid)
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: updatePolicyUserID,
		Action: repository.AuditTracePolicyUpdated, TargetType: "trace_policy", TargetID: agentID, TargetName: pol.Name,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"policy_id": pol.ID, "policy_name": pol.Name, "enabled": pol.Enabled},
	})
	h.pushPoliciesAfterChange(agentID)
	// Answer the stored row, as GetPolicy does: the request body has no
	// created_at, hit count or the fields the upsert keeps.
	if stored, serr := h.Repo.EBPF.ListTracePoliciesByAgent(c.UserContext(), agentID); serr == nil {
		if row := findStoredPolicy(stored, pid); row != nil {
			return c.JSON(rowToPolicy(row))
		}
	}
	return c.JSON(pol)
}

// DeletePolicy removes a stored policy and pushes the agent's policies over
// gRPC.
//
//	DELETE /api/projects/:id/ebpf/trace/policies/:policyId
func (h *HostPolicyHandler) DeletePolicy(c *fiber.Ctx) error {
	policyID := c.Params("policyId")
	agentID, projectID, err := h.resolveAgentAndProject(c)
	if err != nil {
		return err
	}
	pid, ok := parsePolicyID(policyID)
	if !ok {
		return invalidPolicyID(c)
	}
	deletePolicyUserID, _ := c.Locals("user_id").(string)
	rows, lerr := h.Repo.EBPF.ListTracePoliciesByAgent(c.UserContext(), agentID)
	if lerr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete policy"})
	}
	if !hasStoredPolicy(rows, pid) {
		return policyNotFound(c)
	}
	if derr := h.Repo.EBPF.DeleteTracePolicyByPolicyID(c.UserContext(), agentID, pid); derr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete policy"})
	}
	log.Printf("[trace policy] policy %d deleted", pid)
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: deletePolicyUserID,
		Action: repository.AuditTracePolicyDeleted, TargetType: "trace_policy", TargetID: agentID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"policy_id": pid},
	})
	h.pushPoliciesAfterChange(agentID)
	return c.JSON(fiber.Map{"status": "deleted", "policy_id": pid})
}

// policyToRow converts the agent-facing struct into a TracePolicyRow ready
// for the persistence layer.
func policyToRow(agentID string, p *hostpolicy.EnforcementPolicy) *repository.TracePolicyRow {
	pid := int(p.ID)
	row := &repository.TracePolicyRow{
		AgentID: agentID, PolicyID: &pid,
		Name: p.Name, Description: p.Description, Enabled: p.Enabled,
		EventTypes: p.EventTypes, MinSeverity: p.MinSeverity,
		MatchComm: p.MatchComm, MatchCommMode: p.MatchCommMode, MatchFilename: p.MatchFilename,
		MatchUID: p.MatchUID, MatchDestPort: p.MatchDestPort, MatchDestIP: p.MatchDestIP,
		Action: p.Action, KillAcknowledged: p.KillAcknowledged,
		KernelEnforce: p.KernelEnforce, KernelEnforceRequested: p.KernelEnforceRequested,
		AutoDowngraded: p.AutoDowngraded, EnforcementMode: p.EnforcementMode,
		MITRETechniqueID: p.MITRETechniqueID, MITRETechniqueName: p.MITRETechniqueName,
		MITRETactic: p.MITRETactic, Severity: p.Severity, Tags: p.Tags,
		HitCount: clampInt64FromUint64(p.HitCount),
	}
	return row
}

// hasStoredPolicy reports whether policy pid is among an agent's persisted rows.
func hasStoredPolicy(rows []repository.TracePolicyRow, pid int) bool {
	return findStoredPolicy(rows, pid) != nil
}

// findStoredPolicy is policy pid among an agent's persisted rows, or nil.
func findStoredPolicy(rows []repository.TracePolicyRow, pid int) *repository.TracePolicyRow {
	for i := range rows {
		if rows[i].PolicyID != nil && *rows[i].PolicyID == pid {
			return &rows[i]
		}
	}
	return nil
}

// parsePolicyID reads a trace policy id from the path: a positive decimal
// integer that fits the agent's uint32 ids.
func parsePolicyID(s string) (int, bool) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return int(n), true
}

func invalidPolicyID(c *fiber.Ctx) error {
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid policy id", "code": "INVALID_POLICY_ID"})
}

func policyNotFound(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "policy not found", "code": "NOT_FOUND"})
}

// existingCommMatchMode is the stored match_comm_mode of policy pid among an
// agent's persisted rows, or "" when the row is not there.
func existingCommMatchMode(rows []repository.TracePolicyRow, pid int) string {
	for i := range rows {
		if rows[i].PolicyID != nil && *rows[i].PolicyID == pid {
			return rows[i].MatchCommMode
		}
	}
	return ""
}

// rowToPolicy reverses policyToRow for serving cached state to the dashboard.
func rowToPolicy(row *repository.TracePolicyRow) *hostpolicy.EnforcementPolicy {
	p := &hostpolicy.EnforcementPolicy{
		Name: row.Name, Description: row.Description, Enabled: row.Enabled,
		EventTypes: row.EventTypes, MinSeverity: row.MinSeverity,
		MatchComm: row.MatchComm, MatchCommMode: row.MatchCommMode, MatchFilename: row.MatchFilename,
		MatchUID: row.MatchUID, MatchDestPort: row.MatchDestPort, MatchDestIP: row.MatchDestIP,
		Action: row.Action, KillAcknowledged: row.KillAcknowledged,
		KernelEnforce: row.KernelEnforce, KernelEnforceRequested: row.KernelEnforceRequested,
		AutoDowngraded: row.AutoDowngraded, EnforcementMode: row.EnforcementMode,
		MITRETechniqueID: row.MITRETechniqueID, MITRETechniqueName: row.MITRETechniqueName,
		MITRETactic: row.MITRETactic, Severity: row.Severity, Tags: row.Tags,
		HitCount:  clampUint64FromInt64(row.HitCount),
		CreatedAt: row.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt: row.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if row.PolicyID != nil {
		p.ID = clampUint32(*row.PolicyID)
	}
	return p
}

// ClearEnforcementLog deletes all stored enforcement log entries of the
// agent.
//
// Only the stored rows are cleared: agents have no HTTP callback (migration
// 000031), so an agent may still send entries it buffered before the clear;
// cleared_at lets the dashboard hide those.
//
//	DELETE /api/ebpf/trace/enforcement-log
func (h *HostPolicyHandler) ClearEnforcementLog(c *fiber.Ctx) error {
	agentID, projectID, err := h.resolveAgentAndProject(c)
	if err != nil {
		return err
	}

	// Take the clear time before deleting, so the dashboard can hide
	// entries that arrive late.
	clearedAt := time.Now().UTC()

	// Delete + VACUUM the DB rows.
	if err := h.Repo.EBPF.ClearEnforcementLog(c.UserContext(), agentID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	clearUserID, _ := c.Locals("user_id").(string)
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: clearUserID,
		Action: repository.AuditFirewallLogCleared, TargetType: "agent", TargetID: agentID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"cleared_at": clearedAt.Format(time.RFC3339)},
	})
	return c.JSON(fiber.Map{"status": "cleared", "cleared_at": clearedAt.Format(time.RFC3339Nano)})
}

// ── Port Policy endpoints (enterprise ingress/egress port firewall) ─────────

// ListPortPolicies returns port policies from the desired state.
//
//	GET /api/ebpf/port-policies?agent_id=<uuid>
func (h *HostPolicyHandler) ListPortPolicies(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	if s.PortPolicies == nil {
		s.PortPolicies = []hostpolicy.PortPolicyAPI{}
	}
	cfg := s.PortPolicyConfig
	if cfg == nil {
		cfg = &hostpolicy.PortPolicyConfigAPI{Enabled: false, DefaultIngress: "allow", DefaultEgress: "allow"}
	}
	return c.JSON(fiber.Map{
		"policies": s.PortPolicies,
		"config":   cfg,
		"count":    len(s.PortPolicies),
	})
}

// AddPortPolicy adds a port policy to the desired state and pushes to agent.
//
//	POST /api/ebpf/port-policies
func (h *HostPolicyHandler) AddPortPolicy(c *fiber.Ctx) error {
	agentID, projectID, err := h.resolveAgentAndProject(c)
	if err != nil {
		return err
	}
	// Flexible parser: single object, bare array, or {"policies":[...]}
	var policies []hostpolicy.PortPolicyAPI
	body := c.Body()
	if len(body) > 0 {
		// Try {"policies":[...]}
		var wrapper struct {
			Policies []hostpolicy.PortPolicyAPI `json:"policies"`
		}
		if err := json.Unmarshal(body, &wrapper); err == nil && len(wrapper.Policies) > 0 {
			policies = wrapper.Policies
		} else if err := json.Unmarshal(body, &policies); err != nil {
			// Try single object
			var single hostpolicy.PortPolicyAPI
			if err := json.Unmarshal(body, &single); err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid port policy"})
			}
			policies = []hostpolicy.PortPolicyAPI{single}
		}
	}
	if len(policies) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "at least one policy required"})
	}
	for i, p := range policies {
		if err := hostpolicy.ValidatePortPolicyRule(p); err != nil {
			return desiredStateWriteError(c, err)
		}
		policies[i] = hostpolicy.CanonicalPortPolicy(p)
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	addPortPolicies(s, policies)
	warnings, err := h.writeState(c.UserContext(), agentID, projectID, s)
	if err != nil {
		return desiredStateWriteError(c, err)
	}
	ppUserID, _ := c.Locals("user_id").(string)
	ports := make([]any, 0, len(policies))
	for _, p := range policies {
		ports = append(ports, map[string]any{"port": p.Port, "proto": p.Proto, "direction": p.Direction})
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: ppUserID,
		Action: repository.AuditFirewallPortPolicyAdded, TargetType: "agent", TargetID: agentID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"policies": ports},
	})
	return jsonWithWarnings(c, fiber.Map{"status": "ok", "count": len(s.PortPolicies)}, warnings)
}

// DeletePortPolicy removes a port policy from the desired state and pushes to agent.
//
//	DELETE /api/ebpf/port-policies
func (h *HostPolicyHandler) DeletePortPolicy(c *fiber.Ctx) error {
	agentID, projectID, err := h.resolveAgentAndProject(c)
	if err != nil {
		return err
	}
	var req struct {
		Port      uint16 `json:"port"`
		Proto     string `json:"proto"`
		Direction string `json:"direction"`
	}
	// Accept body or query params
	if len(c.Body()) > 0 {
		if err := json.Unmarshal(c.Body(), &req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
		}
	} else {
		if p, _ := strconv.Atoi(c.Query("port")); p > 0 && p <= math.MaxUint16 {
			req.Port = uint16(p)
		}
		req.Proto = c.Query("proto")
		req.Direction = c.Query("direction")
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	removePortPolicies(s, []hostpolicy.PortPolicyAPI{{Port: req.Port, Proto: req.Proto, Direction: req.Direction}})
	warnings, err := h.writeState(c.UserContext(), agentID, projectID, s)
	if err != nil {
		return desiredStateWriteError(c, err)
	}
	ppDelUserID, _ := c.Locals("user_id").(string)
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: ppDelUserID,
		Action: repository.AuditFirewallPortPolicyRemoved, TargetType: "agent", TargetID: agentID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"port": req.Port, "proto": req.Proto, "direction": req.Direction},
	})
	return jsonWithWarnings(c, fiber.Map{"status": "ok", "count": len(s.PortPolicies)}, warnings)
}

// GetPortPolicyConfig returns port policy config from the desired state.
//
//	GET /api/ebpf/port-policies/config
func (h *HostPolicyHandler) GetPortPolicyConfig(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	if s.PortPolicyConfig != nil {
		return c.JSON(s.PortPolicyConfig)
	}
	return c.JSON(fiber.Map{"enabled": false, "default_ingress": "allow", "default_egress": "allow"})
}

// UpdatePortPolicyConfig updates the port policy config in the desired state and
// pushes to agent.
//
//	PUT /api/ebpf/port-policies/config
func (h *HostPolicyHandler) UpdatePortPolicyConfig(c *fiber.Ctx) error {
	agentID, projectID, err := h.resolveAgentAndProject(c)
	if err != nil {
		return err
	}
	var cfg hostpolicy.PortPolicyConfigAPI
	if err := json.Unmarshal(c.Body(), &cfg); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid config body", "code": "BAD_REQUEST"})
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	s.PortPolicyConfig = &cfg
	warnings, err := h.writeState(c.UserContext(), agentID, projectID, s)
	if err != nil {
		return desiredStateWriteError(c, err)
	}
	ppCfgUserID, _ := c.Locals("user_id").(string)
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: ppCfgUserID,
		Action: repository.AuditFirewallPortCfgUpdated, TargetType: "agent", TargetID: agentID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"enabled": cfg.Enabled, "default_ingress": cfg.DefaultIngress, "default_egress": cfg.DefaultEgress},
	})
	return jsonWithWarnings(c, cfg, warnings)
}

// ── Egress Blocklist endpoints ──────────────────────────────────────────────

// ListEgressBlocklist returns one page of the egress blocklist from the
// desired state (expired entries hidden; see desiredListPage).
//
//	GET /api/projects/:id/host/egress-blocklist?agent_id=<uuid>&limit=&offset=
func (h *HostPolicyHandler) ListEgressBlocklist(c *fiber.Ctx) error {
	agentID, err := h.resolveAgentID(c)
	if err != nil {
		return err
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	return desiredListPage(c, prunedEgressBlocklist(s.EgressBlocklist))
}

// AddEgressBlocklist adds a single entry to the egress blocklist and pushes to agent.
//
//	POST /api/ebpf/egress-blocklist
func (h *HostPolicyHandler) AddEgressBlocklist(c *fiber.Ctx) error {
	agentID, projectID, err := h.resolveAgentAndProject(c)
	if err != nil {
		return err
	}
	var req struct {
		Entries []struct {
			IP    string `json:"ip"`
			TTLMs int64  `json:"ttl_ms"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(c.Body(), &req); err != nil || len(req.Entries) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "entries required"})
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	entries := make([]hostpolicy.IPEntry, 0, len(req.Entries))
	for _, r := range req.Entries {
		entries = append(entries, hostpolicy.IPEntry{IP: r.IP, TTLMs: r.TTLMs})
	}
	// IPv6 egress entries need a TC object that filters IPv6: the host
	// reports it in its status (egress_ipv6_supported); unknown = refused.
	added, err := addEgressBlocklist(s, entries, time.Now().UTC(), func() bool {
		return h.agentEgressIPv6Supported(c.UserContext(), agentID)
	})
	if errors.Is(err, errEgressIPv6Unsupported) {
		return invalidInput(c, "EGRESS_IPV6_UNSUPPORTED", err)
	}
	if err != nil {
		return ipListError(c, "egress blocklist", err)
	}
	warnings, err := h.writeState(c.UserContext(), agentID, projectID, s)
	if err != nil {
		return desiredStateWriteError(c, err)
	}
	egAddUserID, _ := c.Locals("user_id").(string)
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: egAddUserID,
		Action: repository.AuditFirewallEgressAdded, TargetType: "agent", TargetID: agentID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"count": added},
	})
	return jsonWithWarnings(c, fiber.Map{"status": "ok", "added": added, "count": len(s.EgressBlocklist)}, warnings)
}

// DeleteEgressBlocklist removes an entry from the egress blocklist and pushes to agent.
//
//	DELETE /api/ebpf/egress-blocklist
func (h *HostPolicyHandler) DeleteEgressBlocklist(c *fiber.Ctx) error {
	agentID, projectID, err := h.resolveAgentAndProject(c)
	if err != nil {
		return err
	}
	var req struct {
		Entries []struct {
			IP string `json:"ip"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(c.Body(), &req); err != nil || len(req.Entries) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "entries required"})
	}
	s, stateErr := h.readState(c.UserContext(), agentID)
	if stateErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "desired state unavailable", "code": "STATE_UNAVAILABLE"})
	}
	removed := removeEgressBlocklist(s, entryIPs(req.Entries))
	warnings, err := h.writeState(c.UserContext(), agentID, projectID, s)
	if err != nil {
		return desiredStateWriteError(c, err)
	}
	egDelUserID, _ := c.Locals("user_id").(string)
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: egDelUserID,
		Action: repository.AuditFirewallEgressRemoved, TargetType: "agent", TargetID: agentID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: map[string]any{"count": removed},
	})
	return jsonWithWarnings(c, fiber.Map{"status": "ok", "removed": removed, "count": len(s.EgressBlocklist)}, warnings)
}

// agentEgressIPv6Supported reports whether the host's last status says its
// attached TC object filters IPv6 egress traffic (ebpf.Status
// EgressIPv6Supported). No status, or an unreadable one, is false.
func (h *HostPolicyHandler) agentEgressIPv6Supported(ctx context.Context, agentID string) bool {
	if h.Repo == nil || h.Repo.EBPF == nil {
		return false
	}
	raw, _, err := h.Repo.EBPF.LatestStatus(ctx, agentID)
	if err != nil {
		return false
	}
	return reportedEgressIPv6(raw)
}

// reportedEgressIPv6 reads egress_ipv6_supported from a stored status
// payload ({"ebpf": {...}}, or the bare status of older agents).
func reportedEgressIPv6(raw []byte) bool {
	var status struct {
		EgressIPv6Supported bool `json:"egress_ipv6_supported"`
		EBPF                *struct {
			EgressIPv6Supported bool `json:"egress_ipv6_supported"`
		} `json:"ebpf"`
	}
	if json.Unmarshal(raw, &status) != nil {
		return false
	}
	if status.EBPF != nil {
		return status.EBPF.EgressIPv6Supported
	}
	return status.EgressIPv6Supported
}

// hasIPv6Entry reports an IPv6 address, prefix or range among list entries.
func hasIPv6Entry(entries []string) bool {
	for _, e := range entries {
		if strings.Contains(e, ":") {
			return true
		}
	}
	return false
}

// ── Project-wide aggregate endpoints ───────────────────────────────────────

// resolveProjectAgentList returns non-WAF agents for the project, optionally
// narrowed to a single agent (?agent_id=) or a specific host (?host_id=).
//
// Priority: agent_id > host_id > all project agents.
// agent_id is used when agents are registered via gRPC mTLS (host_id is NULL).
// host_id  is used when agents are registered via Host Key (host_id is set).
func (h *HostPolicyHandler) resolveProjectAgentList(c *fiber.Ctx) ([]repository.EBPFAgent, error) {
	projectID, err := h.resolveProjectID(c)
	if err != nil {
		return nil, err
	}

	if agentID := c.Query("agent_id"); agentID != "" {
		agent, err := h.Repo.EBPF.GetAgentByID(c.UserContext(), agentID)
		if err != nil || agent == nil || agent.ProjectID != projectID {
			return []repository.EBPFAgent{}, nil
		}
		return []repository.EBPFAgent{*agent}, nil
	}

	if hostID := c.Query("host_id"); hostID != "" {
		// Scoped in SQL rather than filtered afterwards: the predicate belongs
		// next to the query so a later edit cannot drop it and still look right.
		agents, err := h.Repo.EBPF.ListNonWAFAgentsByHostInProject(c.UserContext(), hostID, projectID)
		if err != nil {
			return nil, err
		}
		filtered := make([]repository.EBPFAgent, 0, len(agents))
		for _, agent := range agents {
			if agent.ProjectID == projectID {
				filtered = append(filtered, agent)
			}
		}
		return filtered, nil
	}

	return h.Repo.EBPF.ListAgentsByProject(c.UserContext(), projectID)
}

// resolveProjectAgentIDs returns all non-WAF agent IDs registered for the project,
// filtered to a specific host when ?host_id= is present.
func (h *HostPolicyHandler) resolveProjectAgentIDs(c *fiber.Ctx) ([]string, error) {
	agents, err := h.resolveProjectAgentList(c)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(agents))
	for i, a := range agents {
		ids[i] = a.ID
	}
	return ids, nil
}

func severityNameToInt(name string) int {
	switch name {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	}
	return 0
}

// GetAggregateStatus returns online/firewall/trace status aggregated across all
// host agents in a project.
//
//	GET /api/projects/:id/host/aggregate/status
func (h *HostPolicyHandler) GetAggregateStatus(c *fiber.Ctx) error {
	agents, err := h.resolveProjectAgentList(c)
	if err != nil {
		return err
	}

	const livenessWindow = 90 * time.Second
	type agentSummary struct {
		ID              string     `json:"id"`
		Name            string     `json:"name"`
		Online          bool       `json:"online"`
		FirewallRunning bool       `json:"firewall_running"`
		FirewallCapable bool       `json:"firewall_capable"`
		TraceRunning    bool       `json:"trace_running"`
		TraceCapable    bool       `json:"trace_capable"`
		LastSeen        *time.Time `json:"last_seen,omitempty"`
	}

	// Fetch all status payloads in one batch query instead of N round-trips.
	agentIDs := make([]string, len(agents))
	for i, a := range agents {
		agentIDs[i] = a.ID
	}
	statusMap, _ := h.Repo.EBPF.BatchLatestStatus(c.UserContext(), agentIDs)

	summaries := make([]agentSummary, 0, len(agents))
	var onlineCount, firewallCount, traceCount, firewallCapCount, traceCapCount int

	for _, a := range agents {
		online := a.LastSeen != nil && time.Since(*a.LastSeen) <= livenessWindow

		var firewallCap, traceCap bool
		if payload := statusMap[a.ID]; len(payload) > 0 {
			var wrapper map[string]json.RawMessage
			if err2 := json.Unmarshal(payload, &wrapper); err2 == nil {
				if ebpfRaw, ok := wrapper["ebpf"]; ok {
					var ebpfObj struct {
						Running bool `json:"running"`
					}
					if json.Unmarshal(ebpfRaw, &ebpfObj) == nil && ebpfObj.Running {
						firewallCap = true
					}
				}
				if traceRaw, ok := wrapper["trace"]; ok {
					var traceObj struct {
						Running bool `json:"running"`
					}
					if json.Unmarshal(traceRaw, &traceObj) == nil && traceObj.Running {
						traceCap = true
					}
				}
			}
		}

		effectiveFirewall := online && firewallCap
		effectiveTrace := online && traceCap

		if online {
			onlineCount++
		}
		if firewallCap {
			firewallCapCount++
		}
		if traceCap {
			traceCapCount++
		}
		if effectiveFirewall {
			firewallCount++
		}
		if effectiveTrace {
			traceCount++
		}
		summaries = append(summaries, agentSummary{
			ID:              a.ID,
			Name:            a.Name,
			Online:          online,
			FirewallRunning: effectiveFirewall,
			FirewallCapable: firewallCap,
			TraceRunning:    effectiveTrace,
			TraceCapable:    traceCap,
			LastSeen:        a.LastSeen,
		})
	}

	return c.JSON(fiber.Map{
		"total_agents":     len(agents),
		"agents_online":    onlineCount,
		"firewall_running": firewallCount,
		"firewall_capable": firewallCapCount,
		"trace_running":    traceCount,
		"trace_capable":    traceCapCount,
		"agents":           summaries,
	})
}

// GetAggregateMetrics returns metrics summed across all host agents in a project.
//
//	GET /api/projects/:id/host/aggregate/metrics
func (h *HostPolicyHandler) GetAggregateMetrics(c *fiber.Ctx) error {
	agentIDs, err := h.resolveProjectAgentIDs(c)
	if err != nil {
		return err
	}
	m, err := h.Repo.EBPF.AggregateMetrics(c.UserContext(), agentIDs)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	if m == nil {
		c.Set("Content-Type", "application/json")
		return c.Send([]byte("null"))
	}
	return c.JSON(m)
}

// GetAggregateFirewallEvents returns merged firewall events from all host agents in a project.
//
//	GET /api/projects/:id/host/aggregate/events?limit=N
func (h *HostPolicyHandler) GetAggregateFirewallEvents(c *fiber.Ctx) error {
	agentIDs, err := h.resolveProjectAgentIDs(c)
	if err != nil {
		return err
	}
	limit := boundedLimit(c, 50)
	events, err := h.Repo.EBPF.RecentEventsMulti(c.UserContext(), agentIDs, limit)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	if events == nil {
		events = []repository.EBPFEventRow{}
	}
	return c.JSON(fiber.Map{"events": events, "count": len(events)})
}

// GetAggregateTraceStats returns trace stats summed across all host agents in a project.
//
//	GET /api/projects/:id/host/aggregate/trace/stats
func (h *HostPolicyHandler) GetAggregateTraceStats(c *fiber.Ctx) error {
	agentIDs, err := h.resolveProjectAgentIDs(c)
	if err != nil {
		return err
	}
	payload, err := h.Repo.EBPF.AggregateTraceStats(c.UserContext(), agentIDs)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	c.Set("Content-Type", "application/json")
	return c.Send(payload)
}

// GetAggregateTraceEvents returns merged trace events from all host agents in a project.
//
//	GET /api/projects/:id/host/aggregate/trace/events?limit=N&min_severity=high
func (h *HostPolicyHandler) GetAggregateTraceEvents(c *fiber.Ctx) error {
	agentIDs, err := h.resolveProjectAgentIDs(c)
	if err != nil {
		return err
	}
	limit := boundedLimit(c, 50)
	minSev := severityNameToInt(c.Query("min_severity", "info"))
	events, err := h.Repo.EBPF.RecentTraceEventsMulti(c.UserContext(), agentIDs, minSev, limit)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	if events == nil {
		events = []repository.TraceEventRow{}
	}
	return c.JSON(events)
}

// GetFirewallTopIPs returns the top source IPs by firewall drop count for all
// host agents in the project, with per-reason breakdown and GeoIP enrichment.
//
// GET /api/projects/:id/host/firewall/top-ips?limit=20&range=24h
func (h *HostPolicyHandler) GetFirewallTopIPs(c *fiber.Ctx) error {
	agentIDs, err := h.resolveProjectAgentIDs(c)
	if err != nil {
		return err
	}
	limit, _ := strconv.Atoi(c.Query("limit", "20"))
	if limit < 1 || limit > 100 {
		limit = 20
	}

	window := application.ParseFirewallRange(c.Query("range", "all"), time.Now().UTC())

	analytics := h.firewallAnalytics()
	analytics.NoteViewed(c.Params("id"))
	jsonBytes, err := analytics.TopIPs(c.UserContext(), c.Params("id"), agentIDs, window, limit)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	c.Set("Content-Type", "application/json")
	return c.Send(jsonBytes)
}

// GetFirewallDropsSummary returns total drop counts per reason from the historical event log.
//
// GET /api/projects/:id/host/firewall/drops-summary
func (h *HostPolicyHandler) GetFirewallDropsSummary(c *fiber.Ctx) error {
	agentIDs, err := h.resolveProjectAgentIDs(c)
	if err != nil {
		return err
	}
	window := application.ParseFirewallRange(c.Query("range", "all"), time.Now().UTC())
	var counts map[string]int64
	if len(agentIDs) > 0 {
		counts, err = h.Repo.EBPF.FirewallDropsSummaryRange(c.UserContext(), agentIDs, window.SinceTs, 0)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to load firewall drop summary"})
		}
	}
	// Every documented reason, also when the store returns fewer (none
	// without a host event store).
	return c.JSON(fiber.Map{"drops": application.MergeFirewallDropsSummary(counts)})
}

// GetFirewallAnalytics returns executive-level analytics for the firewall dashboard.
//
// GET /api/projects/:id/host/firewall/analytics?range=24h&agent_id=xxx&host_id=yyy
func (h *HostPolicyHandler) GetFirewallAnalytics(c *fiber.Ctx) error {
	agents, err := h.resolveProjectAgentList(c)
	if err != nil {
		return err
	}

	window := application.ParseFirewallRange(c.Query("range", "all"), time.Now().UTC())
	analytics := h.firewallAnalytics()
	analytics.NoteViewed(c.Params("id"))

	jsonBytes, err := analytics.Analytics(c.UserContext(), c.Params("id"), agents, window)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to compute analytics"})
	}

	c.Set("Content-Type", "application/json")
	return c.Send(jsonBytes)
}

func desiredStateWriteError(c *fiber.Ctx, err error) error {
	// Lockout guard: 400 with a stable code the Firewall lockout-check
	// panel keys on, and the guard's own sentence (it names the port or
	// family to fix) as the message.
	if code, ok := hostpolicy.FirewallErrorCode(err); ok {
		return writeClientError(c, code, err, "The firewall change would lock the host out.")
	}
	if errors.Is(err, repository.ErrDesiredStateConflict) {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "desired state changed; reload and retry", "code": "STATE_CONFLICT"})
	}
	slog.Error("desired_state_write_failed", "path", c.Path(), "err", err)
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error", "code": "INTERNAL_ERROR"})
}
