package httpadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// The bundle carries fcgi_keep_conn only while the option is on, so an agent that does not know the
// key, and a stored bundle from before it, read the same thing: off.
func TestDBBundleCarriesFCGIKeepConnOnlyWhenOn(t *testing.T) {
	m := newMaintenanceFixture(t)
	_, appID := createTestRoute(t, m.dbFixture, "fcgi-bundle", 18085, map[string]any{
		"upstream": "fcgi:127.0.0.1:9000", "fcgi_keep_conn": true,
	})
	keepConn := func() (value any, present bool) {
		t.Helper()
		loaded, _, err := m.srv.BundleLoader.LoadBundle(context.Background(), m.project, "fcgi-bundle-edge")
		if err != nil {
			t.Fatal(err)
		}
		sent, _ := engine.NormalizeBundle(loaded)
		var bundle struct {
			Apps []map[string]any `json:"apps"`
		}
		if err := json.Unmarshal(sent, &bundle); err != nil {
			t.Fatal(err)
		}
		for _, a := range bundle.Apps {
			if a["app_id"] == appID {
				value, present = a["fcgi_keep_conn"]
				return value, present
			}
		}
		t.Fatalf("app %s is not in the bundle: %s", appID, sent)
		return nil, false
	}
	if v, ok := keepConn(); !ok || v != true {
		t.Fatalf("option on: fcgi_keep_conn = %v (present %v), want true", v, ok)
	}
	url := "/api/projects/" + m.project + "/apps/" + appID
	wantStatus(t, "turn it off", call(t, m.app, http.MethodPut, url, m.tokens["owner"], map[string]any{"fcgi_keep_conn": false}), fiber.StatusOK, "")
	if v, ok := keepConn(); ok {
		t.Fatalf("option off: the bundle still has fcgi_keep_conn = %v", v)
	}
}
