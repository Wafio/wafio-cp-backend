package handlers

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// AuditHandler serves the "Audit Log" UI page for a project. Read-only.
type AuditHandler struct {
	Repo *repository.Repository
}

// List returns paginated audit events for a project.
//
// Query params: action (comma-separated prefixes); limit (default 20, max 100)
// and offset, the pagination every other list uses. The older page (default
// 1) and per_page (default 20, max 100) are still accepted; limit/offset win
// when both are sent. The response carries both forms.
//
//	GET /api/projects/:id/audit-log?action=&limit=&offset=
func (h *AuditHandler) List(c *fiber.Ctx) error {
	projectID := c.Params("id")
	if _, err := h.Repo.Project.GetByID(c.UserContext(), projectID); err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found", "code": "PROJECT_NOT_FOUND"})
	}

	// Parse comma-separated action prefixes (e.g. "app.,waf." for WAF tab)
	var prefixes []string
	if raw := c.Query("action"); raw != "" {
		for _, p := range strings.Split(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				prefixes = append(prefixes, p)
			}
		}
	}

	limit, offset := auditPageParams(c)

	events, total, err := h.Repo.Audit.ListByProject(c.UserContext(), projectID, prefixes, limit, offset)
	if err != nil {
		apiErr := ResolveDBError(err, "audit")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	return c.JSON(fiber.Map{
		"events":   events,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
		"page":     offset/limit + 1,
		"per_page": limit,
	})
}

// auditPageParams resolves limit/offset, falling back to page/per_page.
func auditPageParams(c *fiber.Ctx) (limit, offset int) {
	if c.Query("limit") != "" || c.Query("offset") != "" {
		limit = c.QueryInt("limit", 20)
		if limit < 1 {
			limit = 20
		}
		if limit > 100 {
			limit = 100
		}
		offset = c.QueryInt("offset", 0)
		if offset < 0 {
			offset = 0
		}
		return limit, offset
	}
	limit = c.QueryInt("per_page", 20)
	if limit < 1 || limit > 100 {
		limit = 20
	}
	page := c.QueryInt("page", 1)
	if page < 1 {
		page = 1
	}
	return limit, (page - 1) * limit
}
