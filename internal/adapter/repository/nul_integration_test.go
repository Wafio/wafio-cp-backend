package repository

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

// This exercises InsertDecisions against a real PostgreSQL server. It is the
// only way to check the claim the sanitiser rests on: that the database refuses
// a NUL and accepts the U+FFFD written in its place. Unit tests cannot show it.
//
// Skipped unless TEST_DB_URL is set, like the other database-backed tests here.
// The table is created plain rather than as a hypertable; TimescaleDB is not
// installed on the box this ran against, and the NUL question does not involve
// it.
const nulTestDDL = `
CREATE TABLE IF NOT EXISTS waf_decisions (
    id             bigserial,
    agent_id       uuid        NOT NULL,
    app_id         uuid,
    host           text,
    method         text,
    uri            text,
    remote_addr    text,
    country_code   text,
    user_agent     text,
    content_type   text,
    action         text        NOT NULL,
    score          int         NOT NULL DEFAULT 0,
    categories     text[]      NOT NULL DEFAULT '{}',
    cwe            text,
    match_detail   text,
    analyze_method text,
    body_size      int         NOT NULL DEFAULT 0,
    latency_us     int         NOT NULL DEFAULT 0,
    body_preview   text,
    event_time     timestamptz NOT NULL,
    recorded_at    timestamptz NOT NULL DEFAULT NOW(),
    match_source   text,
    request_headers jsonb,
    request_body   text,
    query_params   text,
    payload_type   text,
    coverage       text,
    PRIMARY KEY (id, recorded_at)
);
ALTER TABLE waf_decisions ADD COLUMN IF NOT EXISTS coverage text;`

func nulTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	p, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := p.Exec(context.Background(), nulTestDDL); err != nil {
		t.Fatalf("create table: %v", err)
	}
	return p
}

func decisionWithNUL(agentID string) WAFDecision {
	const nul = "\x00"
	return WAFDecision{
		AgentID:        agentID,
		Host:           "www.example.com",
		Method:         "GET",
		URI:            "/etc/passwd" + nul + ".jpg",
		RemoteAddr:     "203.0.113.9",
		Action:         "block",
		UserAgent:      "sqlmap/1.7" + nul,
		BodyPreview:    "binary" + nul + "payload",
		Categories:     []string{"lfi", "gener" + nul + "ic"},
		RequestHeaders: map[string]string{"X-Junk" + nul: "v" + nul},
		RequestBody:    "id=1" + nul,
		QueryParams:    "q=" + nul,
		Coverage:       "body_decompress_error" + nul,
		EventTime:      time.Now().UTC(),
	}
}

// Without the sanitiser this INSERT fails with "null character not permitted"
// and, because COPY is all-or-nothing inside its transaction, takes every other
// decision in the batch with it.
func TestInsertDecisionsAcceptsNULBearingDecision(t *testing.T) {
	p := nulTestPool(t)
	// A cleanup, not a defer: the fixture cleanup below must run first.
	t.Cleanup(p.Close)
	repo := &WAFRepo{pool: p}
	agentID := uuid.NewString()
	// The migrated schema enforces agent tenancy. Seed the referenced agent so
	// this regression reaches the NUL sanitizer instead of failing a foreign key.
	var hasAgents bool
	if err := p.QueryRow(context.Background(), `SELECT to_regclass('agents') IS NOT NULL`).Scan(&hasAgents); err != nil {
		t.Fatal(err)
	}
	if hasAgents {
		// Seed our own project: a freshly migrated database has none.
		projectID, userID := dbfixture.SeedProject(t, p)
		if _, err := p.Exec(context.Background(), `INSERT INTO agents(id,user_id,project_id,name,kind) VALUES ($1,$2,$3,'NUL regression','waf')`, agentID, userID, projectID); err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = p.Exec(context.Background(), `DELETE FROM agents WHERE id=$1`, agentID) }()
	}

	rows := []WAFDecision{
		{AgentID: agentID, Action: "allow", URI: "/good-1", EventTime: time.Now().UTC()},
		decisionWithNUL(agentID),
		{AgentID: agentID, Action: "allow", URI: "/good-2", EventTime: time.Now().UTC()},
	}
	if err := repo.InsertDecisions(context.Background(), rows); err != nil {
		t.Fatalf("batch containing a NUL was rejected: %v", err)
	}

	var n int
	if err := p.QueryRow(context.Background(),
		`SELECT count(*) FROM waf_decisions WHERE agent_id = $1`, agentID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 3 {
		t.Fatalf("stored %d of 3 decisions; the batch was not written whole", n)
	}

	var uri, ua, preview string
	if err := p.QueryRow(context.Background(),
		`SELECT uri, user_agent, body_preview FROM waf_decisions
		 WHERE agent_id = $1 AND action = 'block'`, agentID).Scan(&uri, &ua, &preview); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if strings.ContainsRune(uri, 0) {
		t.Errorf("a NUL reached the column: %q", uri)
	}
	// The point of replacing rather than stripping: the record must not read as
	// an ordinary image request.
	if uri == "/etc/passwd.jpg" {
		t.Error("the NUL was stripped, turning an attack into plausible traffic")
	}
	if !strings.HasPrefix(uri, "/etc/passwd") || !strings.HasSuffix(uri, ".jpg") {
		t.Errorf("evidence around the NUL was lost: %q", uri)
	}
	t.Logf("stored uri=%q user_agent=%q body_preview=%q", uri, ua, preview)

	// jsonb is the stricter column; confirm the header map survived.
	var hdr string
	if err := p.QueryRow(context.Background(),
		`SELECT request_headers::text FROM waf_decisions
		 WHERE agent_id = $1 AND action = 'block'`, agentID).Scan(&hdr); err != nil {
		t.Fatalf("read headers: %v", err)
	}
	t.Logf("stored request_headers=%s", hdr)

	var coverage string
	if err := p.QueryRow(context.Background(),
		`SELECT coverage FROM waf_decisions
		 WHERE agent_id = $1 AND action = 'block'`, agentID).Scan(&coverage); err != nil {
		t.Fatalf("read coverage: %v", err)
	}
	if strings.ContainsRune(coverage, 0) || !strings.HasPrefix(coverage, "body_decompress_error") {
		t.Errorf("coverage not stored sanitised: %q", coverage)
	}

	_, _ = p.Exec(context.Background(), `DELETE FROM waf_decisions WHERE agent_id = $1`, agentID)
}

// The control: the same decision, unsanitised, must be refused. If this ever
// stops failing, the sanitiser is guarding against nothing and the test above
// proves nothing.
func TestRawNULIsStillRejectedByPostgres(t *testing.T) {
	p := nulTestPool(t)
	defer p.Close()

	_, err := p.Exec(context.Background(),
		`INSERT INTO waf_decisions (agent_id, action, uri, event_time) VALUES ($1,$2,$3,NOW())`,
		uuid.NewString(), "block", "/etc/passwd\x00.jpg")
	if err == nil {
		t.Fatal("PostgreSQL accepted a NUL; the premise of sanitize.go no longer holds")
	}
	t.Logf("confirmed, PostgreSQL refuses it: %v", err)
}
