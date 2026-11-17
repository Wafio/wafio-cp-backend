package handlers

import (
	"encoding/json"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
)

// Names reach the installer's root terminal and
// the dashboard, so a host or agent name or a label value carrying an
// ESC/BEL/CSI/OSC sequence, a C1 control or a bidi/format character is
// refused with 400 before any repository access (the handlers run without a
// database here; acceptance of non-ASCII names is in names_db_test.go).
var unsafeNames = []string{
	"\x1b]0;pwn\x07",           // OSC title set
	"ok\x1b]52;c;cHdu\x07",     // OSC 52 clipboard write
	"ok\x1b]8;;http://x\x1b\\", // OSC 8 hyperlink
	"a\x1b[2Jb",                // CSI clear screen
	"bell\x07ring",
	"tab\tname",
	"c1\u009b31m",
	"bidi\u202egnp",
	"zw\u200bname",
	"bom\ufeffname",
}

func namesTestApp() *fiber.App {
	app := fiber.New()
	app.Use(recover.New())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(auth.UserIDKey, "u1")
		c.Locals("user_id", "u1")
		return c.Next()
	})
	hosts := &HostsHandler{}
	app.Post("/api/projects/:id/hosts", hosts.Create)
	app.Post("/api/projects/:id/hosts/labels", hosts.UpdateLabels)
	app.Post("/api/projects/:id/agents", (&AgentManagerHandler{}).RegisterAgent)
	app.Post("/api/projects/:id/host/agents", (&HostPolicyHandler{}).RegisterAgent)
	return app
}

func jsonString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestUnsafeNamesRejected(t *testing.T) {
	app := namesTestApp()
	const pid = "11111111-1111-1111-1111-111111111111"
	for _, name := range unsafeNames {
		n := jsonString(t, name)
		for _, tc := range []struct {
			what, path, body, code string
		}{
			{"host name", "/api/projects/" + pid + "/hosts", `{"name":` + n + `}`, "VALIDATION_FAILED"},
			{"host label on create", "/api/projects/" + pid + "/hosts", `{"name":"edge-1","labels":{"env":` + n + `}}`, "INVALID_LABELS"},
			{"host label edit", "/api/projects/" + pid + "/hosts/labels",
				`{"host_ids":["22222222-2222-2222-2222-222222222222"],"set":{"env":` + n + `}}`, "INVALID_LABELS"},
			{"agent name", "/api/projects/" + pid + "/agents", `{"name":` + n + `,"kind":"waf"}`, "VALIDATION_FAILED"},
			{"host agent name", "/api/projects/" + pid + "/host/agents", `{"name":` + n + `}`, "VALIDATION_FAILED"},
		} {
			status, got := doJSON(t, app, "POST", tc.path, "member", tc.body)
			if status != fiber.StatusBadRequest || got["code"] != tc.code {
				t.Errorf("%s %q: %d %v, want 400 %s", tc.what, name, status, got, tc.code)
			}
		}
	}
}
