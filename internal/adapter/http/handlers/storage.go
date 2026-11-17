package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
)

// StorageHandler serves Administration › Data retention (system admin only,
// under /api/admin): telemetry retention per table, the database size
// budget and the size alert.
type StorageHandler struct {
	Svc *application.Storage
	// Repo writes the audit rows (nil in handler-only tests).
	Repo *repository.Repository
	// LogAudit replaces Repo.Audit.LogSystem (tests).
	LogAudit func(context.Context, repository.SystemAuditEvent) error
}

// maxStorageBody bounds a PUT body (five tables).
const maxStorageBody = 8 << 10

// GetStatus returns retention, size and compression per table and the
// database size status.
//
//	GET /api/admin/storage
func (h *StorageHandler) GetStatus(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	st, err := h.Svc.Status(c.UserContext())
	if err != nil {
		return storageUnavailable(c)
	}
	return c.JSON(st)
}

// GetAlert returns the last background size check (no database query), for
// the Administration banner and the header indicator.
//
//	GET /api/admin/storage/alert
func (h *StorageHandler) GetAlert(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.JSON(h.Svc.Alert())
}

// UpdateRetention sets the retention of one or more tables (days, null =
// default) and applies it at once; returns the new status.
//
//	PUT /api/admin/storage/retention {"tables": {"waf_decisions": 14}}
func (h *StorageHandler) UpdateRetention(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	const action = "admin.retention_updated"
	var body application.RetentionUpdate
	if len(c.Body()) > maxStorageBody || c.BodyParser(&body) != nil {
		h.audit(c, action, "data_retention", fiber.StatusBadRequest, nil)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "VALIDATION_FAILED"})
	}
	changes, err := h.Svc.UpdateRetention(c.UserContext(), body)
	if status := storageError(c, err); status != 0 {
		h.audit(c, action, "data_retention", status, nil)
		return nil
	}
	// The row records old → new days per changed table and where the
	// retention runs.
	h.audit(c, action, "data_retention", fiber.StatusOK, map[string]any{"tables": changes})
	return h.statusAfterSave(c)
}

// UpdateBudget sets or removes the database size budget (GB, decimal).
//
//	PUT /api/admin/storage/budget {"budget_gb": 50}
func (h *StorageHandler) UpdateBudget(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	const action = "admin.storage_budget_updated"
	var body application.BudgetUpdate
	// budget_gb must be present: null removes the budget, so an empty or
	// misspelled body must not.
	var keys map[string]json.RawMessage
	if len(c.Body()) > maxStorageBody || c.BodyParser(&body) != nil || json.Unmarshal(c.Body(), &keys) != nil || keys["budget_gb"] == nil {
		h.audit(c, action, "db_size_budget", fiber.StatusBadRequest, nil)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Enter a size in GB, or null to remove the budget.", "code": "VALIDATION_FAILED", "field": "budget_gb"})
	}
	oldBytes, newBytes, err := h.Svc.UpdateBudget(c.UserContext(), body)
	if status := storageError(c, err); status != 0 {
		h.audit(c, action, "db_size_budget", status, nil)
		return nil
	}
	h.audit(c, action, "db_size_budget", fiber.StatusOK, map[string]any{"old_bytes": oldBytes, "new_bytes": newBytes})
	return h.statusAfterSave(c)
}

// statusAfterSave answers a committed save with the new status, or
// {"ok": true} when the status cannot be read right now (the save stands).
func (h *StorageHandler) statusAfterSave(c *fiber.Ctx) error {
	st, err := h.Svc.Status(c.UserContext())
	if err != nil {
		return c.JSON(fiber.Map{"ok": true})
	}
	return c.JSON(st)
}

// storageError answers a service error and returns its status (0 = nil).
func storageError(c *fiber.Ctx, err error) int {
	var inv *application.StorageInvalid
	switch {
	case err == nil:
		return 0
	case errors.As(err, &inv):
		code := inv.Code
		if code == "" {
			code = "VALIDATION_FAILED"
		}
		_ = c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": inv.Message, "code": code, "field": inv.Field})
		return fiber.StatusBadRequest
	default:
		_ = storageUnavailable(c)
		return fiber.StatusServiceUnavailable
	}
}

func storageUnavailable(c *fiber.Ctx) error {
	return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
		"error": "Unable to read or change the storage settings. Check the database connection.",
		"code":  "STORAGE_UNAVAILABLE",
	})
}

// audit writes a system audit row (target type system_setting).
func (h *StorageHandler) audit(c *fiber.Ctx, action, targetID string, status int, metadata map[string]any) {
	logAudit := h.LogAudit
	if logAudit == nil {
		if h.Repo == nil || h.Repo.Audit == nil {
			return
		}
		logAudit = h.Repo.Audit.LogSystem
	}
	outcome := "success"
	if status >= 400 {
		outcome = "failure"
	}
	actorID, _ := c.Locals(auth.UserIDKey).(string)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = logAudit(ctx, repository.SystemAuditEvent{
		ActorUserID: actorID, Action: action, TargetType: "system_setting", TargetID: targetID,
		Outcome: outcome, HTTPStatus: status, IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		Metadata: metadata,
	})
}
