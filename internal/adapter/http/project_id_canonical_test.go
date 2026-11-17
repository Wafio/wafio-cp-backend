package httpadapter

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
)

// A project id that is not the canonical UUID spelling is the same 404 as an
// unknown project, for admins and members alike, so per-project state keyed
// by the URL id (apply locks, agent streams) sees one spelling per project.
func TestRequireProjectAccessRejectsNonCanonicalID(t *testing.T) {
	app := newTestFiberApp(t)
	id := uuid.NewString()
	userID := uuid.NewString()
	testUsers.put(userID, auth.UserState{Exists: true, Role: "user"})
	userTok, err := auth.SignJWT(userID, "user@example.test", "user", secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	route := func(pid string) string { return "/api/projects/" + pid + "/hosts/apply/firewall" }

	// Canonical id, admin: reaches the handler (invalid body → 400).
	if r := call(t, app, http.MethodPost, route(id), adminToken(t), "x"); r.status != fiber.StatusBadRequest {
		t.Fatalf("canonical id: %d %s", r.status, r.raw)
	}
	for _, pid := range []string{
		strings.ToUpper(id),
		"{" + id + "}",
		"urn:uuid:" + id,
		strings.ReplaceAll(id, "-", ""),
		"not-a-uuid",
	} {
		for _, tok := range []string{adminToken(t), userTok} {
			r := call(t, app, http.MethodPost, route(pid), tok, "x")
			if r.status != fiber.StatusNotFound || r.body["error"] != "project not found" {
				t.Fatalf("id %q: %d %s, want 404 project not found", pid, r.status, r.raw)
			}
		}
	}
}
