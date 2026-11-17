package handlers

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

type ProjectMembersHandler struct {
	Repo *repository.Repository
}

// ListMembers returns the project's members, paged with ?limit= (≤ 100;
// omitted = up to 100) and ?offset=.
//
//	GET /api/projects/:id/members?limit=&offset=
func (h *ProjectMembersHandler) ListMembers(c *fiber.Ctx) error {
	projectID := c.Params("id")
	all, err := h.Repo.ProjectMember.List(c.UserContext(), projectID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list members", "code": "INTERNAL_ERROR"})
	}
	page := parsePage(c, maxListLimit)
	members := pageOf(all, page)
	out := make([]fiber.Map, 0, len(members))
	for _, m := range members {
		out = append(out, fiber.Map{
			"id":         m.ID,
			"project_id": m.ProjectID,
			"user_id":    m.UserID,
			"user_email": m.UserEmail,
			"user_name":  m.UserName,
			"role":       m.Role,
			"created_at": m.CreatedAt,
		})
	}
	return c.JSON(fiber.Map{"members": out, "total": len(all), "limit": page.Limit, "offset": page.Offset})
}

// The role vocabulary is declared once, in the tag, so it cannot drift from the
// CHECK constraint added in migration 000064.
type addMemberRequest struct {
	UserID string `json:"user_id" validate:"required,uuid4"`
	Role   string `json:"role"    validate:"required,oneof=viewer member owner"`
}

// memberEvent is the audit row of a membership change (member
// changes are always audited). The target is the member's user id. The
// repository writes it in the transaction of the change itself.
func memberEvent(c *fiber.Ctx, projectID, action, targetUserID string, meta map[string]any) repository.AuditEvent {
	callerID, _ := c.Locals(auth.UserIDKey).(string)
	return repository.AuditEvent{
		ProjectID: projectID, ActorUserID: callerID,
		Action: action, TargetType: "user", TargetID: targetUserID,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: meta,
	}
}

func memberNotFound(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "member not found", "code": "MEMBER_NOT_FOUND"})
}

func (h *ProjectMembersHandler) AddMember(c *fiber.Ctx) error {
	projectID := c.Params("id")
	var body addMemberRequest
	if err := BindJSON(c, &body); err != nil {
		return err
	}
	ev := memberEvent(c, projectID, repository.AuditMemberAdded, body.UserID, map[string]any{"role": body.Role})
	added, err := h.Repo.ProjectMember.AddAudited(c.UserContext(), projectID, body.UserID, body.Role, ev)
	if err != nil {
		if isForeignKeyViolation(err) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found", "code": "USER_NOT_FOUND"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to add member", "code": "INTERNAL_ERROR"})
	}
	if !added {
		// The stored role is kept and nothing is audited; changing a role
		// is PUT …/members/:userId.
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "user is already a member of this project", "code": "ALREADY_MEMBER"})
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"ok": true})
}

type updateMemberRoleRequest struct {
	Role string `json:"role" validate:"required,oneof=viewer member owner"`
}

// UpdateMemberRole changes a member's role. 404 when the user is not a
// member of the project; 409 LAST_OWNER when it would demote the only owner.
func (h *ProjectMembersHandler) UpdateMemberRole(c *fiber.Ctx) error {
	projectID := c.Params("id")
	targetUserID := c.Params("userId")
	var body updateMemberRoleRequest
	if err := BindJSON(c, &body); err != nil {
		return err
	}
	ev := memberEvent(c, projectID, repository.AuditMemberRoleChanged, targetUserID, map[string]any{"role": body.Role})
	switch err := h.Repo.ProjectMember.UpdateRoleAudited(c.UserContext(), projectID, targetUserID, body.Role, ev); {
	case err == nil:
		return c.JSON(fiber.Map{"ok": true})
	case errors.Is(err, repository.ErrMemberNotFound):
		return memberNotFound(c)
	case errors.Is(err, repository.ErrLastOwner):
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "the project must keep at least one owner", "code": "LAST_OWNER"})
	default:
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update role", "code": "INTERNAL_ERROR"})
	}
}

// RemoveMember removes a member. Removing the only owner stays 400 (the
// documented contract); the owner check and the delete share one locked
// transaction, so two concurrent removals cannot leave the project ownerless.
// Removing a user who is not a member is a no-op 200, as before.
func (h *ProjectMembersHandler) RemoveMember(c *fiber.Ctx) error {
	projectID := c.Params("id")
	targetUserID := c.Params("userId")
	ev := memberEvent(c, projectID, repository.AuditMemberRemoved, targetUserID, nil)
	switch err := h.Repo.ProjectMember.RemoveAudited(c.UserContext(), projectID, targetUserID, ev); {
	case err == nil, errors.Is(err, repository.ErrMemberNotFound):
		return c.JSON(fiber.Map{"ok": true})
	case errors.Is(err, repository.ErrLastOwner):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "cannot remove the last owner"})
	default:
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to remove member", "code": "INTERNAL_ERROR"})
	}
}
