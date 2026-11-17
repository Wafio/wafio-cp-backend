package handlers

import (
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestFeedbackRejectsInvalidIdentityAndVerdictBeforeStorage(t *testing.T) {
	handler := WAFFeedbackHandler{}
	app := fiber.New()
	app.Post("/decisions/:decisionId/feedback", handler.Create)
	for _, tc := range []struct{ path, body string }{
		{"/decisions/0/feedback?recorded_at=2026-09-11T00:00:00Z", `{"verdict":"unsure"}`},
		{"/decisions/1/feedback", `{"verdict":"unsure"}`},
		{"/decisions/1/feedback?recorded_at=2026-09-11T00:00:00Z", `{"verdict":"allowlist"}`},
		{"/decisions/1/feedback?recorded_at=2026-09-11T00:00:00Z", `{"verdict":"unsure","note":"` + strings.Repeat("x", 2001) + `"}`},
	} {
		req := httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		res, err := apicontract.TestOperation(t, app, "POST /api/projects/{id}/apps/{appId}/waf/decisions/{decisionId}/feedback", req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 400 {
			t.Fatalf("status=%d", res.StatusCode)
		}
	}
}
