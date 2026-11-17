package agentserver

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

// HostBundleApplyStatus is connection-local evidence, not durable desired-state CAS.
// Disconnect removes this evidence; callers must display unknown when absent.
type HostBundleApplyStatus struct {
	CommandID         string `json:"command_id"`
	DesiredGeneration int64  `json:"desired_generation,string"`
	AppliedGeneration int64  `json:"applied_generation,string"`
	// Status: pending | applied | failed | refused. "refused" means the
	// agent's lockout guard rejected the state before changing anything;
	// the host keeps its previous (last good) policy.
	Status string `json:"status"`
	// Code is the lockout-guard code of a refusal (SSH_ALLOW_REQUIRED, …).
	Code string `json:"code,omitempty"`
	// Source (ebpf_state only): which policy the host enforces — "saved"
	// (last good, restored from disk at agent start), "default" (nothing
	// restored), "live" (a push from this control plane was applied).
	Source          string `json:"source,omitempty"`
	SavedGeneration int64  `json:"saved_generation,omitempty,string"`
	// DNSRelaxed: the saved egress Deny All runs with DNS allowed because
	// the agent could not pin its control-plane endpoints at start.
	DNSRelaxed bool      `json:"dns_relaxed,omitempty"`
	Error      string    `json:"error,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// deliveryDefaults: explicit values for desired-state sections that were
// never saved — no rules, port policies off, the agent's start-up config.
var deliveryDefaults = func() map[string]json.RawMessage {
	cfg, err := json.Marshal(hostpolicy.DefaultFullConfigAPI())
	if err != nil {
		panic(err)
	}
	return map[string]json.RawMessage{
		"config":             cfg,
		"blocklist":          json.RawMessage(`[]`),
		"allowlist":          json.RawMessage(`[]`),
		"geo_blocked":        json.RawMessage(`[]`),
		"geo_mode":           json.RawMessage(`"block"`),
		"port_policies":      json.RawMessage(`[]`),
		"egress_blocklist":   json.RawMessage(`[]`),
		"port_policy_config": json.RawMessage(`{"enabled":false,"default_ingress":"allow","default_egress":"allow"}`),
	}
}()

// refusalCode parses "apply refused (CODE): …" written by the host agent
// (wafio-agent-host internal/agent/firewall_last_good.go refuseApply).
func refusalCode(msg string) (string, bool) {
	rest, ok := strings.CutPrefix(msg, "apply refused (")
	if !ok {
		return "", false
	}
	code, _, ok := strings.Cut(rest, ")")
	if !ok || code == "" || len(code) > 64 || strings.ContainsAny(code, " \t\n") {
		return "", false
	}
	return code, true
}

func (h *streamHandle) sendHostBundle(kind string, msg *agentv1.ServerMessage) error {
	h.bundleSendMu.Lock()
	defer h.bundleSendMu.Unlock()
	b := msg.GetBundle()
	h.bundleMu.Lock()
	if h.bundleStates == nil {
		h.bundleStates = make(map[string]HostBundleApplyStatus)
	}
	previous := h.bundleStates[kind]
	if b.GetGeneration() < previous.DesiredGeneration {
		h.bundleMu.Unlock()
		return fmt.Errorf("stale desired-state generation")
	}
	h.bundleStates[kind] = HostBundleApplyStatus{
		CommandID: b.GetCommandId(), DesiredGeneration: b.GetGeneration(), AppliedGeneration: previous.AppliedGeneration,
		Status: "pending", Source: previous.Source, SavedGeneration: previous.SavedGeneration,
		DNSRelaxed: previous.DNSRelaxed, UpdatedAt: time.Now().UTC(),
	}
	h.bundleMu.Unlock()
	if err := h.send(msg); err != nil {
		h.recordHostBundleAck(&agentv1.CommandAck{CommandId: b.GetCommandId(), Ok: false, Error: err.Error()})
		return err
	}
	return nil
}

func (h *streamHandle) recordHostBundleAck(ack *agentv1.CommandAck) {
	h.bundleMu.Lock()
	defer h.bundleMu.Unlock()
	for kind, state := range h.bundleStates {
		if state.CommandID != ack.GetCommandId() {
			continue
		}
		state.Status = "failed"
		state.Code = ""
		state.Error = ack.GetError()
		if code, ok := refusalCode(state.Error); ok {
			state.Status = "refused"
			state.Code = code
		}
		if ack.GetOk() {
			state.Status = "applied"
			state.AppliedGeneration = state.DesiredGeneration
			state.Error = ""
			state.Code = ""
			if kind == "ebpf_state" {
				state.Source = "live"
				state.DNSRelaxed = false
			}
		}
		state.UpdatedAt = time.Now().UTC()
		h.bundleStates[kind] = state
	}
}

// hostPolicySourceCommandID is the CommandAck a host agent sends on connect
// with the policy in force ({"source":"saved|default|live","generation":…},
// JSON in the error field — wafio-agent-host internal/agent/firewall_last_good.go).
const hostPolicySourceCommandID = "ebpf:policy_source"

// recordPolicySource stores the reported source on the ebpf_state status.
func (h *streamHandle) recordPolicySource(payload string) {
	var info struct {
		Source     string `json:"source"`
		Generation int64  `json:"generation,string"`
		DNSRelaxed bool   `json:"dns_relaxed"`
	}
	if json.Unmarshal([]byte(payload), &info) != nil {
		return
	}
	switch info.Source {
	case "saved", "default", "live":
	default:
		return
	}
	h.bundleMu.Lock()
	defer h.bundleMu.Unlock()
	if h.bundleStates == nil {
		h.bundleStates = make(map[string]HostBundleApplyStatus)
	}
	state := h.bundleStates["ebpf_state"]
	state.Source = info.Source
	state.SavedGeneration = 0
	state.DNSRelaxed = false
	if info.Source == "saved" {
		state.SavedGeneration = info.Generation
		state.DNSRelaxed = info.DNSRelaxed
	}
	if state.Status == "" {
		state.Status = "unknown"
	}
	state.UpdatedAt = time.Now().UTC()
	h.bundleStates["ebpf_state"] = state
}

// HostBundleStatus returns acknowledged state only for the requested tenant/agent.
func (s *Server) HostBundleStatus(agentID, projectID string) map[string]HostBundleApplyStatus {
	return s.AgentBundleStatus(agentID, projectID)
}

// EBPFStateApplied reports whether the agent has acked the latest
// ebpf_state bundle as applied. Used by the reconnect push loop to decide
// whether desired-state delivery is complete. Only the ebpf_state kind
// counts: an applied trace-policy or detection-rule resync says nothing
// about the firewall, and stopping the retry loop on it could leave a host
// that restarted with an empty rule table.
func (s *Server) EBPFStateApplied(agentID, projectID string) bool {
	state, ok := s.AgentBundleStatus(agentID, projectID)["ebpf_state"]
	return ok && state.Status == "applied" && state.AppliedGeneration >= state.DesiredGeneration
}

// AgentBundleStatus includes WAF, firewall and trace configuration ACKs.
// Management-only commands never enter this tracker.
func (s *Server) AgentBundleStatus(agentID, projectID string) map[string]HostBundleApplyStatus {
	result := make(map[string]HostBundleApplyStatus)
	if s == nil {
		return result
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, h := range s.streams {
		if (h.agentID != agentID && h.ebpfAgentID != agentID) || h.projectID != projectID {
			continue
		}
		h.bundleMu.Lock()
		for kind, state := range h.bundleStates {
			result[kind] = state
		}
		h.bundleMu.Unlock()
	}
	return result
}

// EBPFStateSummaries returns the ebpf_state delivery status of every
// connected host agent of one project, keyed by agent id, in one
// read-locked pass over the streams (the fleet view; never per agent).
// Another project's streams are never read.
func (s *Server) EBPFStateSummaries(projectID string) map[string]domain.BundleApplyState {
	out := make(map[string]domain.BundleApplyState)
	if s == nil || projectID == "" {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, h := range s.streams {
		if h.projectID != projectID || h.ebpfAgentID == "" {
			continue
		}
		h.bundleMu.Lock()
		state, ok := h.bundleStates["ebpf_state"]
		h.bundleMu.Unlock()
		if ok {
			out[h.ebpfAgentID] = domain.BundleApplyState{Status: state.Status, Code: state.Code}
		}
	}
	return out
}

// Live counters never belong to policy identity: telemetry can update them
// without changing the persisted configuration revision.
func desiredStateForDelivery(raw json.RawMessage) (json.RawMessage, error) {
	var state map[string]json.RawMessage
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}
	if state == nil {
		state = map[string]json.RawMessage{}
	}
	// The control plane's desired state is authoritative:
	// an absent section is delivered as its explicit empty/default value, so
	// the agent replaces every part of a saved policy instead of keeping
	// what the control plane no longer has.
	for key, def := range deliveryDefaults {
		if value, ok := state[key]; !ok || string(value) == "null" {
			state[key] = def
		}
	}
	if err := splitScopedAllowlist(state); err != nil {
		return nil, err
	}
	for _, key := range []string{"blocklist", "allowlist", "allowlist_scoped", "port_policies", "egress_blocklist"} {
		value, ok := state[key]
		if !ok || string(value) == "null" {
			continue
		}
		var entries []map[string]json.RawMessage
		if err := json.Unmarshal(value, &entries); err != nil {
			return nil, err
		}
		for _, entry := range entries {
			delete(entry, "hit_count")
		}
		encoded, err := json.Marshal(entries)
		if err != nil {
			return nil, err
		}
		state[key] = encoded
	}
	return json.Marshal(state)
}

// splitScopedAllowlist moves every allowlist entry that carries ports into
// "allowlist_scoped". A host
// agent older than port scopes decodes an entry's unknown "ports" field away
// and would enforce the entry on every port; under a key of its own the
// entry is ignored instead (fail closed). An entry whose "ports" is anything
// but absent, null or [] counts as scoped, so a malformed value never
// reaches an old agent as a full entry. Stored states keep every entry under
// "allowlist"; an "allowlist_scoped" already present is merged in.
func splitScopedAllowlist(state map[string]json.RawMessage) error {
	var full, scoped []map[string]json.RawMessage
	if raw, ok := state["allowlist"]; ok && string(raw) != "null" {
		var entries []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil {
			return err
		}
		full = make([]map[string]json.RawMessage, 0, len(entries))
		for _, entry := range entries {
			if portsScoped(entry["ports"]) {
				scoped = append(scoped, entry)
				continue
			}
			delete(entry, "ports")
			full = append(full, entry)
		}
		encoded, err := json.Marshal(full)
		if err != nil {
			return err
		}
		state["allowlist"] = encoded
	}
	if raw, ok := state["allowlist_scoped"]; ok && string(raw) != "null" {
		var entries []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil {
			return err
		}
		scoped = append(scoped, entries...)
	}
	if scoped == nil {
		scoped = []map[string]json.RawMessage{}
	}
	encoded, err := json.Marshal(scoped)
	if err != nil {
		return err
	}
	state["allowlist_scoped"] = encoded
	return nil
}

// portsScoped: an entry's "ports" value restricts it (anything but absent,
// null or an empty array).
func portsScoped(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return false
	}
	var items []json.RawMessage
	return json.Unmarshal(raw, &items) != nil || len(items) > 0
}
