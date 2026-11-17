package handlers

import (
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestRollbackRequiresRevisionAndCASBeforeStorage(t *testing.T) {
	app := fiber.New()
	handler := AgentManagerHandler{}
	app.Post("/history/:revision/rollback", handler.RollbackAppConfig)
	for _, tc := range []struct {
		revision, body string
		status         int
	}{
		{"-1", `{"expected_revision":0}`, 400},
		{"invalid", `{"expected_revision":0}`, 400},
		{"0", `{}`, 428},
		{"0", `{"expected_revision":-1}`, 428},
		{"0", `{"expected_revision":"0"}`, 400},
	} {
		req := httptest.NewRequest("POST", "/history/"+tc.revision+"/rollback", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		res, err := apicontract.TestOperation(t, app, "POST /api/projects/{id}/apps/{appId}/waf/config-history/{revision}/rollback", req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != tc.status {
			t.Fatalf("revision=%s body=%s status=%d want=%d", tc.revision, tc.body, res.StatusCode, tc.status)
		}
	}
}
