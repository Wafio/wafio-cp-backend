package handlers

import (
	"errors"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type WAFFeedbackHandler struct {
	Repo *repository.Repository
	// SummarySvc serves Summary.
	SummarySvc *application.FeedbackSummary
}

func feedbackIdentity(c *fiber.Ctx) (int64, time.Time, error) {
	id, err := strconv.ParseInt(c.Params("decisionId"), 10, 64)
	if err != nil || id <= 0 {
		return 0, time.Time{}, errors.New("invalid decision ID")
	}
	at, err := time.Parse(time.RFC3339Nano, c.Query("recorded_at"))
	return id, at, err
}

func (h *WAFFeedbackHandler) List(c *fiber.Ctx) error {
	id, at, err := feedbackIdentity(c)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "decision ID and recorded_at are required"})
	}
	limit, offset := c.QueryInt("limit", 20), c.QueryInt("offset", 0)
	if limit < 1 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	rows, total, err := h.Repo.WAF.ListDecisionFeedback(c.UserContext(), c.Params("id"), c.Params("appId"), id, at, limit, offset)
	if errors.Is(err, pgx.ErrNoRows) {
		return c.Status(404).JSON(fiber.Map{"error": "decision not found"})
	}
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to load feedback"})
	}
	return c.JSON(fiber.Map{"feedback": rows, "total": total})
}

func (h *WAFFeedbackHandler) Create(c *fiber.Ctx) error {
	id, at, err := feedbackIdentity(c)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "decision ID and recorded_at are required"})
	}
	var body struct {
		Verdict string `json:"verdict"`
		Note    string `json:"note"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	body.Note = strings.TrimSpace(body.Note)
	if !domain.ValidFeedbackVerdict(body.Verdict) || utf8.RuneCountInString(body.Note) > 2000 {
		return c.Status(400).JSON(fiber.Map{"error": "choose true_positive, false_positive or unsure; note must be at most 2000 characters"})
	}
	actor, _ := c.Locals(auth.UserIDKey).(string)
	feedback, err := h.Repo.WAF.AddDecisionFeedback(c.UserContext(), domain.WAFDecisionFeedback{ProjectID: c.Params("id"), AppID: c.Params("appId"), DecisionID: id, DecisionRecordedAt: at, ActorUserID: actor, Verdict: body.Verdict, Note: body.Note})
	if errors.Is(err, pgx.ErrNoRows) {
		return c.Status(404).JSON(fiber.Map{"error": "decision not found"})
	}
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to save feedback"})
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{ProjectID: feedback.ProjectID, ActorUserID: actor, Action: "waf.feedback.created", TargetType: "waf_decision_feedback", TargetID: feedback.ID, IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()), MetadataJSON: map[string]any{"verdict": body.Verdict, "decision_id": id, "decision_recorded_at": at}})
	return c.Status(201).JSON(feedback)
}

// Summary serves GET /api/projects/:id/waf/feedback/summary: the
// false-positive feedback aggregate of the project, or of one app
// (?app_id=, canonical UUID), over ?range=24h|7d|30d (default 7d).
func (h *WAFFeedbackHandler) Summary(c *fiber.Ctx) error {
	appID := c.Query("app_id")
	if appID != "" {
		if parsed, err := uuid.Parse(appID); err != nil || parsed.String() != appID {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "not found"})
		}
	}
	out, err := h.SummarySvc.Summarize(c.UserContext(), c.Params("id"), c.Query("range"), appID)
	switch {
	case errors.Is(err, application.ErrFeedbackInvalidRange):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "range must be 24h, 7d or 30d", "code": "INVALID_RANGE"})
	case errors.Is(err, application.ErrFeedbackAppNotFound):
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "not found"})
	case err != nil:
		slog.Error("waf_feedback_summary_failed", "project_id", c.Params("id"), "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to load feedback summary"})
	}
	return c.JSON(out)
}
