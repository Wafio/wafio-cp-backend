package httpadapter

import (
	"context"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// The audit-log action filter matches its prefix literally: '_' and '%' are
// not wildcards.
func TestDBAuditActionPrefixIsLiteral(t *testing.T) {
	f := newDBFixture(t)
	ctx := context.Background()
	for _, action := range []string{"zz_fix.one", "zzXfix.two", "zz%fix.three"} {
		if err := f.repo.Audit.Log(ctx, repository.AuditEvent{ProjectID: f.project, ActorUserID: f.userIDs["owner"], Action: action, TargetType: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	for prefix, want := range map[string]float64{"zz_": 1, "zz%25": 1, "zz": 3} {
		r := call(t, f.app, http.MethodGet, "/api/projects/"+f.project+"/audit-log?action="+prefix, f.tokens["owner"], nil)
		wantStatus(t, "audit filter "+prefix, r, fiber.StatusOK, "")
		if r.body["total"] != want {
			t.Errorf("?action=%s matched %v rows, want %v: %s", prefix, r.body["total"], want, r.raw)
		}
	}
}
