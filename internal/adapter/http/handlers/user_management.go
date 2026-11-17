package handlers

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/validate"
	"golang.org/x/crypto/bcrypt"
)

type UserManagementHandler struct {
	Repo *repository.Repository
	// Streams ends the agent streams of the projects a deleted user owned
	// (agentserver.Server in production; nil disables it).
	Streams ProjectStreams
	JWT     struct {
		Secret      string
		ExpireHours int
	}
	// UserStates is RequireJWT's cache of (exists, role, token_version).
	// A role change, delete or password reset invalidates the target's entry
	// so revocation applies on the next request. Nil in tests.
	UserStates *auth.UserStates
}

type listUsersQuery struct {
	Limit  int `query:"limit" validate:"gte=1,lte=100"`
	Offset int `query:"offset" validate:"gte=0"`
}

func (h *UserManagementHandler) ListUsers(c *fiber.Ctx) error {
	q := listUsersQuery{Limit: 20, Offset: 0}
	_ = c.QueryParser(&q)
	if q.Limit == 0 {
		q.Limit = 20
	}
	if err := validate.Struct(&q); err != nil {
		return validationFailed(c, err)
	}
	users, total, err := h.Repo.User.List(c.UserContext(), q.Limit, q.Offset)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list users"})
	}
	out := make([]fiber.Map, 0, len(users))
	for _, u := range users {
		out = append(out, fiber.Map{
			"id":         u.ID,
			"email":      u.Email,
			"name":       u.Name,
			"role":       u.Role,
			"created_at": u.CreatedAt,
		})
	}
	return c.JSON(fiber.Map{"users": out, "total": total})
}

type createUserRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Name     string `json:"name" validate:"required"`
	Password string `json:"password" validate:"required,min=8"`
	Role     string `json:"role" validate:"required,oneof=admin user"`
}

func (h *UserManagementHandler) CreateUser(c *fiber.Ctx) error {
	var body createUserRequest
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if err := validate.Struct(&body); err != nil {
		return validationFailed(c, err)
	}
	if newPasswordTooLong(body.Password) {
		return passwordTooLong(c)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to hash password"})
	}
	user, err := h.Repo.User.CreateWithRole(c.UserContext(), body.Email, string(hash), body.Name, body.Role)
	if err != nil {
		if isUniqueViolation(err) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "email already registered", "code": "CONFLICT"})
		}
		apiErr := ResolveDBError(err, "user")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"id":         user.ID,
		"email":      user.Email,
		"name":       user.Name,
		"role":       user.Role,
		"created_at": user.CreatedAt,
	})
}

func (h *UserManagementHandler) GetUser(c *fiber.Ctx) error {
	userID := c.Params("userId")
	user, err := h.Repo.User.GetByID(c.UserContext(), userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}
	return c.JSON(fiber.Map{
		"id":         user.ID,
		"email":      user.Email,
		"name":       user.Name,
		"role":       user.Role,
		"created_at": user.CreatedAt,
	})
}

type updateUserRequest struct {
	Name string `json:"name"`
	Role string `json:"role" validate:"omitempty,oneof=admin user"`
}

func (h *UserManagementHandler) UpdateUser(c *fiber.Ctx) error {
	callerID, _ := c.Locals(auth.UserIDKey).(string)
	targetID := c.Params("userId")

	var body updateUserRequest
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if err := validate.Struct(&body); err != nil {
		return validationFailed(c, err)
	}
	// Cannot demote yourself
	if callerID == targetID && body.Role != "" && body.Role != "admin" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "cannot remove your own admin role"})
	}
	if body.Name != "" {
		if err := h.Repo.User.UpdateName(c.UserContext(), targetID, body.Name); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update user"})
		}
	}
	if body.Role != "" {
		// A real role change bumps token_version: the user's tokens, minted
		// under the old role, stop working.
		_, err := h.Repo.User.UpdateRole(c.UserContext(), targetID, body.Role)
		h.UserStates.Invalidate(targetID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update role"})
		}
	}
	user, err := h.Repo.User.GetByID(c.UserContext(), targetID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}
	return c.JSON(fiber.Map{
		"id":         user.ID,
		"email":      user.Email,
		"name":       user.Name,
		"role":       user.Role,
		"created_at": user.CreatedAt,
	})
}

func (h *UserManagementHandler) DeleteUser(c *fiber.Ctx) error {
	callerID, _ := c.Locals(auth.UserIDKey).(string)
	targetID := c.Params("userId")
	if callerID == targetID {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "cannot delete yourself"})
	}
	// The delete cascades to the projects the user owns and to their mTLS
	// credentials; read their IDs first so the open agent streams can be
	// ended afterwards. A failed read only loses that fast path: the
	// periodic credential re-check still closes the streams.
	var owned []string
	if h.Streams != nil {
		owned, _ = h.Repo.Project.ListIDsOwnedBy(c.UserContext(), targetID)
	}
	err := h.Repo.User.Delete(c.UserContext(), targetID)
	// The row is gone: RequireJWT rejects the user's tokens once the cached
	// state is dropped.
	h.UserStates.Invalidate(targetID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete user"})
	}
	for _, pid := range owned {
		h.Streams.DisconnectProject(pid)
	}
	return c.JSON(fiber.Map{"ok": true})
}

type resetPasswordRequest struct {
	Password string `json:"password" validate:"required,min=8"`
}

func (h *UserManagementHandler) ResetPassword(c *fiber.Ctx) error {
	targetID := c.Params("userId")
	var body resetPasswordRequest
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if err := validate.Struct(&body); err != nil {
		return validationFailed(c, err)
	}
	if newPasswordTooLong(body.Password) {
		return passwordTooLong(c)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to hash password"})
	}
	// The reset bumps token_version: every session of the user ends.
	_, err = h.Repo.User.UpdatePassword(c.UserContext(), targetID, string(hash))
	h.UserStates.Invalidate(targetID)
	if errors.Is(err, pgx.ErrNoRows) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update password"})
	}
	return c.JSON(fiber.Map{"ok": true})
}

// SearchUsers (GET /api/users/search) was removed. Any
// authenticated user could list the id, email and name of every account,
// across tenants, with a two-character query, and nothing in the dashboard
// called it. A member lookup for an invite UI, if one is ever needed, belongs
// under /api/projects/:id and returns only that project's members.
