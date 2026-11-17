package handlers

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/agentserver"
)

// BlockWindowHandler serves the Block Window API: list and delete active
// block entries tracked by the control plane for LoginProtection and BlockPolicy.
type BlockWindowHandler struct {
	Server *agentserver.Server
	Repo   *repository.Repository
}

type blockEntryResponse struct {
	ID        string                        `json:"id"`
	Key       string                        `json:"key"`
	KeyType   string                        `json:"key_type"`
	Reason    string                        `json:"reason"`
	Path      string                        `json:"path"`
	ExpiresAt time.Time                     `json:"expires_at"`
	BlockedAt time.Time                     `json:"blocked_at"`
	Unblock   *agentserver.UnblockOperation `json:"unblock,omitempty"`
}

// List returns all active (non-expired) block entries for the given agent.
//
// GET /api/projects/:id/agents/:agentId/block-window
func (h *BlockWindowHandler) List(c *fiber.Ctx) error {
	projectID := c.Params("id")
	agentID := c.Params("agentId")
	if projectID == "" || agentID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing project or agent id"})
	}

	if h.Server == nil || h.Server.BlockWindow == nil {
		return c.Status(503).JSON(fiber.Map{"error": "block state unavailable"})
	}
	entries := h.Server.BlockWindow.ListActive(projectID, agentID)
	resp := make([]blockEntryResponse, 0, len(entries))
	for _, e := range entries {
		resp = append(resp, blockEntryResponse{
			ID:        e.ID,
			Unblock:   h.Server.UnblockStatus(projectID, agentID, e.ID),
			Key:       e.Key,
			KeyType:   e.KeyType,
			Reason:    e.Reason,
			Path:      e.Path,
			ExpiresAt: e.ExpiresAt,
			BlockedAt: e.BlockedAt,
		})
	}
	return c.JSON(fiber.Map{"entries": resp})
}

// Delete requests removal; evidence remains until all targeted streams ACK.
//
// DELETE /api/projects/:id/agents/:agentId/block-window/:entryId
func (h *BlockWindowHandler) Delete(c *fiber.Ctx) error {
	projectID := c.Params("id")
	agentID := c.Params("agentId")
	entryID := c.Params("entryId")
	if projectID == "" || agentID == "" || entryID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing parameter"})
	}

	if h.Server == nil || h.Server.BlockWindow == nil {
		return c.Status(503).JSON(fiber.Map{"error": "block state unavailable"})
	}
	operation, err := h.Server.RequestUnblock(projectID, agentID, entryID)
	if err != nil {
		status, code := 503, "UNBLOCK_UNAVAILABLE"
		if errors.Is(err, agentserver.ErrUnblockNotFound) {
			status, code = 404, "NOT_FOUND"
		}
		if errors.Is(err, agentserver.ErrUnblockUnsupported) {
			status, code = 409, "UNBLOCK_UNSUPPORTED"
		}
		// The agentserver sentinels (offline, not found, unsupported, busy)
		// are written for the operator; anything else gets a generic text.
		return c.Status(status).JSON(fiber.Map{"error": clientText(err, "The unblock request could not be sent."), "code": code, "status": "not_sent"})
	}
	if h.Repo != nil {
		userID, _ := c.Locals("user_id").(string)
		_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{ProjectID: projectID, ActorUserID: userID, Action: "waf.unblock_requested", TargetType: "agent", TargetID: agentID, IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()), MetadataJSON: map[string]any{"entry_id": entryID, "status": operation.Status, "command_id": operation.CommandID}})
	}
	return c.Status(fiber.StatusAccepted).JSON(operation)
}
