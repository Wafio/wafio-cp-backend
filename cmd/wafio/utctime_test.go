package main

// This file tests the UTC pin from shared/utctime as wired into cmd/wafio:
// TestUTCPinTakesEffect proves the blank import in main.go actually ran the
// pin, so deleting that import fails a test; TestAPITimestampsAreUTC proves
// the real HTTP app emits "Z"-suffixed timestamps end to end. The pin's own
// mechanics (time.Local, time.Now(), a pgx-decoded timestamptz) are covered
// generically by shared/utctime's own tests.

import (
	"context"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // Asia/Jakarta must resolve even on a host without zoneinfo.

	"github.com/google/uuid"
	httpadapter "github.com/wafio/wafio-cp-backend/internal/adapter/http"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/config"
)

const tzChildEnv = "WAFIO_TZ_CHILD"

// TestUTCPinTakesEffect re-execs the test binary with TZ=Asia/Jakarta so a
// regression — e.g. someone deleting the shared/utctime blank import from
// main.go — shows up here even on a host whose own zone is already UTC.
func TestUTCPinTakesEffect(t *testing.T) {
	if os.Getenv(tzChildEnv) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestUTCPinTakesEffect$", "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), tzChildEnv+"=1", "TZ=Asia/Jakarta")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child under TZ=Asia/Jakarta failed: %v\n%s", err, out)
		}
		t.Logf("child under TZ=Asia/Jakarta:\n%s", out)
		return
	}
	if time.Local != time.UTC {
		t.Fatalf("time.Local = %v under TZ=Asia/Jakarta; cmd/wafio must keep the shared/utctime blank import", time.Local)
	}
}

// jsonTimestamp matches an RFC 3339 string value inside a JSON document.
var jsonTimestamp = regexp.MustCompile(`"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"`)

func assertUTCJSON(t *testing.T, what, body string) {
	t.Helper()
	found := jsonTimestamp.FindAllString(body, -1)
	if len(found) == 0 {
		t.Fatalf("%s: no timestamp in %s", what, body)
	}
	for _, ts := range found {
		if !strings.HasSuffix(ts, `Z"`) {
			t.Errorf("%s: timestamp %s is not UTC (want a \"Z\" suffix)", what, ts)
		}
	}
}

// TestAPITimestampsAreUTC exercises the real app end to end: every timestamp
// in a JSON response must carry a "Z" suffix.
func TestAPITimestampsAreUTC(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	repo, err := repository.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	u, err := repo.User.Create(ctx, uuid.NewString()+"@tz.test", "fixture-hash", "tz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.User.Delete(context.Background(), u.ID) }()
	p, err := repo.Project.Create(ctx, u.ID, "tz", "PRJ-"+strings.ReplaceAll(uuid.NewString(), "-", ""), "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Project.DeleteByID(context.Background(), p.ID) }()

	const secret = "timezone-test-secret-32-chars-min!!"
	cfg := &config.Config{}
	cfg.JWT.Secret = secret
	cfg.JWT.ExpireHours = 1
	cfg.Server.FrontendPath = t.TempDir()
	app := httpadapter.NewFiberApp(ctx, cfg, repo, nil, nil, nil, nil, &handlers.SecurityDataHandler{}, "test")
	tok, err := auth.SignJWT(u.ID, u.Email, "user", secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/api/projects", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 10_000)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	assertUTCJSON(t, "GET /api/projects", string(body))
}
