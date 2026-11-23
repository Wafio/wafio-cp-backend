package httpadapter

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// The app summary takes its window like the other app widgets: no number or a number below one is an
// hour, and more than 30 days is 30 days. Without the cap a window of years reads every decision.
func TestDBAppSummaryClampsMinutes(t *testing.T) {
	f := newDBFixture(t)
	app, err := f.repo.App.Create(context.Background(), &repository.App{ProjectID: f.project, Name: "clamp-" + uuid.NewString()[:6]})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ query, window string }{
		{"", "60m"}, {"?minutes=0", "60m"}, {"?minutes=-5", "60m"}, {"?minutes=30", "30m"},
		{"?minutes=43200", "43200m"}, {"?minutes=43201", "43200m"}, {"?minutes=99999999", "43200m"},
	} {
		r := call(t, f.app, http.MethodGet, "/api/projects/"+f.project+"/apps/"+app.ID+"/waf/summary"+c.query, f.tokens["viewer"], nil)
		if r.status != http.StatusOK || r.body["window"] != c.window {
			t.Errorf("%q: status %d, window %v, want %s (%s)", c.query, r.status, r.body["window"], c.window, r.raw)
		}
	}
}
