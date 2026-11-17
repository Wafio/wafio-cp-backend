package handlers

import (
	"encoding/json"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"io"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// The app decision feed rejects malformed or unbounded parameters
// before touching the database (the handler has no repository here, so any
// request that got past validation would panic).
func TestAppDecisionsRejectsBadParams(t *testing.T) {
	app := fiber.New()
	h := &WAFAgentHandler{}
	app.Get("/api/projects/:id/apps/:appId/waf/decisions", h.AppDecisions)
	cursor := repository.DecisionCursor{RecordedAt: time.Now().UTC(), ID: 7}.Encode()
	now := time.Now().UTC()
	for _, tc := range []struct {
		name, query, code string
	}{
		{"from not RFC3339", "from_ts=yesterday", "WAF_DECISIONS_BAD_RANGE"},
		{"to not RFC3339", "to_ts=1700000000", "WAF_DECISIONS_BAD_RANGE"},
		{"from after to", "from_ts=2026-09-28T10:00:00Z&to_ts=2026-09-28T09:00:00Z", "WAF_DECISIONS_BAD_RANGE"},
		{"empty window", "from_ts=2026-09-28T10:00:00Z&to_ts=2026-09-28T10:00:00Z", "WAF_DECISIONS_BAD_RANGE"},
		{"window over 30d", "from_ts=2026-08-01T00:00:00Z&to_ts=2026-09-28T00:00:00Z", "WAF_DECISIONS_BAD_RANGE"},
		{"from in the future", "from_ts=" + now.Add(time.Hour).Format(time.RFC3339), "WAF_DECISIONS_BAD_RANGE"},
		{"ip substring", "ip=10.0.0", "WAF_DECISIONS_BAD_IP"},
		{"ip cidr", "ip=10.0.0.0/8", "WAF_DECISIONS_BAD_IP"},
		{"ip wildcard", "ip=%25", "WAF_DECISIONS_BAD_IP"},
		{"bad cursor", "cursor=not-a-cursor", "WAF_DECISIONS_BAD_CURSOR"},
		{"cursor with offset", "cursor=" + cursor + "&offset=50", "WAF_DECISIONS_BAD_CURSOR"},
		{"offset too deep", "offset=10001", "WAF_DECISIONS_BAD_OFFSET"},
		{"bad source", "source=grpc", "WAF_DECISIONS_BAD_SOURCE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/projects/p1/apps/a1/waf/decisions?"+tc.query, nil)
			res, err := apicontract.FiberTest(t, app, req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			body, _ := io.ReadAll(res.Body)
			if res.StatusCode != fiber.StatusBadRequest {
				t.Fatalf("status %d body %s", res.StatusCode, body)
			}
			var out struct{ Error, Code string }
			if err := json.Unmarshal(body, &out); err != nil || out.Code != tc.code || out.Error == "" {
				t.Fatalf("body %s, want code %s", body, tc.code)
			}
		})
	}
}

func TestParseAppDecisionsWindow(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	from, to, msg := parseAppDecisionsWindow("", "", now)
	if msg != "" || !to.Equal(now) || !from.Equal(now.Add(-24*time.Hour)) {
		t.Fatalf("default: %s..%s %q", from, to, msg)
	}
	// Only from: to defaults to now.
	from, to, msg = parseAppDecisionsWindow("2026-09-21T12:00:00Z", "", now)
	if msg != "" || !to.Equal(now) || !from.Equal(now.Add(-7*24*time.Hour)) {
		t.Fatalf("from only: %s..%s %q", from, to, msg)
	}
	// Only to: 24 h before it. Offsets are converted to UTC.
	from, to, msg = parseAppDecisionsWindow("", "2026-09-20T07:00:00+07:00", now)
	want := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	if msg != "" || !to.Equal(want) || to.Location() != time.UTC || !from.Equal(want.Add(-24*time.Hour)) {
		t.Fatalf("to only: %s..%s %q", from, to, msg)
	}
	// Exactly 30 days is accepted; fractional seconds parse.
	if _, _, msg = parseAppDecisionsWindow("2026-08-29T12:00:00.5Z", "2026-09-28T12:00:00.5Z", now); msg != "" {
		t.Fatalf("30d window rejected: %q", msg)
	}
	if _, _, msg = parseAppDecisionsWindow(url.QueryEscape("x"), "", now); msg == "" {
		t.Fatal("garbage accepted")
	}
}
