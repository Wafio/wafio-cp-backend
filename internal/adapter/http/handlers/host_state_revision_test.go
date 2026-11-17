package handlers

import (
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

func TestDesiredStateConcurrentWriteReturnsConflict(t *testing.T) {
	app := fiber.New()
	app.Put("/state", func(c *fiber.Ctx) error { return desiredStateWriteError(c, repository.ErrDesiredStateConflict) })
	response, err := apicontract.TestOperation(t, app, "PUT /api/projects/{id}/host/config", httptest.NewRequest("PUT", "/state", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 409 {
		t.Fatalf("status %d", response.StatusCode)
	}
}
