package handlers

import (
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/wafio/wafio-cp-backend/internal/agentserver"
	"github.com/wafio/wafio-cp-backend/internal/dashboard"
)

func (h *WAFAgentHandler) OverviewEvidence(c *fiber.Ctx) error {
	projectID, ok := h.ensureProjectOwner(c)
	if !ok {
		return nil
	}
	if host := c.Query("host_id"); host != "" {
		if _, err := uuid.Parse(host); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid host scope"})
		}
	}
	result, err := h.Repo.WAF.OverviewEvidence(c.UserContext(), projectID, c.Query("host_id"))
	if errors.Is(err, pgx.ErrNoRows) {
		return c.Status(404).JSON(fiber.Map{"error": "scope not found"})
	}
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to load overview evidence"})
	}
	statusReader, supportsStatus := h.AgentServer.(interface {
		AgentBundleStatus(string, string) map[string]agentserver.HostBundleApplyStatus
	})
	if server, ok := h.AgentServer.(*agentserver.Server); ok && server == nil {
		supportsStatus = false
	}
	if !supportsStatus {
		result.Sources["configuration_ack"] = dashboard.EvidenceSource{State: "unavailable", Message: "Agent connection evidence is unavailable"}
	} else {
		observed := time.Now().UTC()
		result.ConnectionObservedAt = &observed
		result.Sources["configuration_ack"] = dashboard.EvidenceSource{State: "connection_local", ObservedAt: &observed, Message: "Evidence is lost on disconnect or control-plane restart; database snapshot is separate"}
		for i := range result.Agents {
			agent := &result.Agents[i]
			states := statusReader.AgentBundleStatus(agent.ID, projectID)
			for kind, state := range states {
				if kind == "waf_config" {
					applied := strconv.FormatInt(state.AppliedGeneration, 10)
					agent.AppliedGeneration = &applied
					agent.ApplyState = state.Status
					at := state.UpdatedAt.UTC()
					agent.ApplyObservedAt = &at
					if agent.DesiredGeneration != nil && *agent.DesiredGeneration != applied && state.Status == "applied" {
						agent.ApplyState = "pending"
					}
				}
				if state.Status != "applied" {
					at := state.UpdatedAt.UTC()
					result.Actions = append(result.Actions, dashboard.OverviewAction{ID: "config:" + agent.ID + ":" + kind, Kind: "configuration", Severity: "warning", TargetID: agent.ID, TargetName: agent.Name, ObservedAt: &at, Message: kind + " configuration " + state.Status + "; application is not confirmed"})
				}
			}
			if agent.Kind == "waf" && agent.DesiredGeneration != nil {
				if agent.ApplyState == "unknown" {
					result.Actions = append(result.Actions, dashboard.OverviewAction{ID: "config:" + agent.ID, Kind: "configuration", Severity: "warning", TargetID: agent.ID, TargetName: agent.Name, Message: "Desired WAF generation " + *agent.DesiredGeneration + " has no current acknowledgement evidence"})
				} else if state, ok := states["waf_config"]; ok && state.Status == "applied" && agent.ApplyState == "pending" {
					result.Actions = append(result.Actions, dashboard.OverviewAction{ID: "config:" + agent.ID, Kind: "configuration", Severity: "warning", TargetID: agent.ID, TargetName: agent.Name, ObservedAt: agent.ApplyObservedAt, Message: "Stored desired WAF generation is newer than the acknowledged generation"})
				}
			}
		}
	}
	sort.SliceStable(result.Actions, func(i, j int) bool {
		rank := map[string]int{"critical": 0, "high": 1, "warning": 2, "info": 3}
		a, b := result.Actions[i], result.Actions[j]
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] < rank[b.Severity]
		}
		return a.ID < b.ID
	})
	result.Total = len(result.Actions)
	limit, offset := c.QueryInt("limit", 20), c.QueryInt("offset", 0)
	if limit < 1 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	if offset > len(result.Actions) {
		offset = len(result.Actions)
	}
	end := min(offset+limit, len(result.Actions))
	result.Actions = result.Actions[offset:end]
	return c.JSON(result)
}
