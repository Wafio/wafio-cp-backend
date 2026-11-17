package agentserver

import (
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// A decision from an agent that does not redact (older than
// the change) is redacted at ingest before it is stored, published to SSE
// subscribers or recorded in the block window; the input the match source
// names keeps its value.
func TestIngestRedactsOldAgentDecisionSecrets(t *testing.T) {
	const red = domain.DecisionRedactedMarker
	env := newE2EEnv(t)
	client := env.dial(t, &env.pki.clientCert)
	sub := env.s.Broker.Subscribe(e2eProject, 8)
	if sub == nil {
		t.Fatal("broker refused subscriber")
	}
	defer env.s.Broker.Unsubscribe(sub)

	st, cancel := openHello(t, client, e2eAgent)
	defer cancel()
	if w := recvWithin(t, st, 5*time.Second).GetWelcome(); w == nil {
		t.Fatal("no welcome")
	}

	if err := st.Send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Decision{Decision: &agentv1.WAFDecisionEvent{
		TsUnix: time.Now().Unix(), AppId: "static", Host: "shop.example:443", Method: "GET",
		Uri: "/search?q=' OR 1=1--&api_key=sk_live_1", RemoteIp: "203.0.113.9", Action: "block", Score: 180,
		Categories: []string{"SQLi"}, MatchSource: "query:q",
		QueryParams: "q=' OR 1=1--&api_key=sk_live_1",
		RequestHeaders: map[string]string{
			"X-Api-Key": "sk_live_2", "Authorization": "Basic dXNlcjpwYXNz",
			"Cookie": "sid=s3cr3t", "User-Agent": "sqlmap",
		},
	}}}); err != nil {
		t.Fatal(err)
	}

	check := func(where string, uri, query string, h map[string]string) {
		t.Helper()
		if uri != "/search?q=' OR 1=1--&api_key="+red {
			t.Errorf("%s uri = %q", where, uri)
		}
		if query != "q=' OR 1=1--&api_key="+red {
			t.Errorf("%s query_params = %q", where, query)
		}
		if h["X-Api-Key"] != red || h["User-Agent"] != "sqlmap" || h["Authorization"] != "" || h["Cookie"] != "" || len(h) != 2 {
			t.Errorf("%s request_headers = %v", where, h)
		}
	}
	select {
	case ev := <-sub.Ch:
		check("published", ev.GetUri(), ev.GetQueryParams(), ev.GetRequestHeaders())
	case <-time.After(5 * time.Second):
		t.Fatal("decision not published")
	}
	waitUntil(t, "decision persisted", func() bool { return len(env.ins.snapshot()) == 1 })
	row := env.ins.snapshot()[0][0]
	check("stored", row.URI, row.QueryParams, row.RequestHeaders)

	waitUntil(t, "block window entry", func() bool { return len(env.s.BlockWindow.ListActive(e2eProject, e2eAgentID)) == 1 })
	if p := env.s.BlockWindow.ListActive(e2eProject, e2eAgentID)[0].Path; p != "/search?q=' OR 1=1--&api_key="+red {
		t.Errorf("block window path = %q", p)
	}
}

// End to end: an agent from before the
// fix guessed match_source "query:<first parameter>" for a verdict, so a
// token in the first parameter arrived named as the evidence. Ingest keeps
// a named secret-named value only when it looks like a payload: the token
// is redacted in the stored row and the published event, the payload stays.
func TestIngestRedactsGuessedMatchSourceSecret(t *testing.T) {
	const red = domain.DecisionRedactedMarker
	env := newE2EEnv(t)
	client := env.dial(t, &env.pki.clientCert)
	sub := env.s.Broker.Subscribe(e2eProject, 8)
	if sub == nil {
		t.Fatal("broker refused subscriber")
	}
	defer env.s.Broker.Unsubscribe(sub)
	st, cancel := openHello(t, client, e2eAgent)
	defer cancel()
	if w := recvWithin(t, st, 5*time.Second).GetWelcome(); w == nil {
		t.Fatal("no welcome")
	}
	const q = "access_token=SECRET123&q=1' UNION SELECT 1--"
	if err := st.Send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Decision{Decision: &agentv1.WAFDecisionEvent{
		TsUnix: time.Now().Unix(), AppId: "static", Host: "shop.example:443", Method: "GET",
		Uri: "/search?" + q, RemoteIp: "203.0.113.9", Action: "log", Score: 90,
		Categories: []string{"SQLi"}, MatchSource: "query:access_token", QueryParams: q,
		RequestHeaders: map[string]string{"Referer": "https://shop.example/a?session=S1&x=1", "X-Api-Key": "<script>, REALSECRET"},
	}}}); err != nil {
		t.Fatal(err)
	}
	const want = "access_token=" + red + "&q=1' UNION SELECT 1--"
	check := func(where, uri, query string, h map[string]string) {
		t.Helper()
		if uri != "/search?"+want || query != want {
			t.Errorf("%s uri %q query %q", where, uri, query)
		}
		if h["Referer"] != "https://shop.example/a?session="+red+"&x=1" || h["X-Api-Key"] != red {
			t.Errorf("%s headers %v", where, h)
		}
	}
	select {
	case ev := <-sub.Ch:
		check("published", ev.GetUri(), ev.GetQueryParams(), ev.GetRequestHeaders())
	case <-time.After(5 * time.Second):
		t.Fatal("decision not published")
	}
	waitUntil(t, "decision persisted", func() bool { return len(env.ins.snapshot()) == 1 })
	row := env.ins.snapshot()[0][0]
	check("stored", row.URI, row.QueryParams, row.RequestHeaders)
}

// End to end: ingest keeps an exact source's flagged
// value (match_source_exact), redacts the same source from an agent without
// the marker, reduces a credential check's value, and redacts secret-named
// body fields of body_preview and request_body.
func TestIngestHonoursExactSourceAndRedactsBodies(t *testing.T) {
	const red = domain.DecisionRedactedMarker
	env := newE2EEnv(t)
	client := env.dial(t, &env.pki.clientCert)
	sub := env.s.Broker.Subscribe(e2eProject, 8)
	if sub == nil {
		t.Fatal("broker refused subscriber")
	}
	defer env.s.Broker.Unsubscribe(sub)
	st, cancel := openHello(t, client, e2eAgent)
	defer cancel()
	if w := recvWithin(t, st, 5*time.Second).GetWelcome(); w == nil {
		t.Fatal("no welcome")
	}
	const payload = "__import__('os').system('id')"
	body := "username=alice&password=" + payload + "&csrf_token=T0K"
	const jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."
	decs := []*agentv1.WAFDecisionEvent{
		// exact body field (current agent)
		{MatchSource: "body:password", MatchSourceExact: true, Categories: []string{"Python"}, ContentType: "form",
			Uri: "/login?code=1", QueryParams: "code=1", BodyPreview: body, RequestBody: body, BodySize: int32(len(body))},
		// same source, no marker (older agent): a guess
		{MatchSource: "body:password", Categories: []string{"Python"}, ContentType: "form",
			Uri: "/login?code=1", QueryParams: "code=1", BodyPreview: body, RequestBody: body},
		// exact query parameter flagged by the JWT engine: reduced
		{MatchSource: "query:token", MatchSourceExact: true, Categories: []string{"JWT"},
			Uri: "/cb?token=" + jwt, QueryParams: "token=" + jwt,
			RequestBody: `{"refresh_token":"R","n":1}`, ContentType: "json"},
	}
	for _, d := range decs {
		d.TsUnix, d.AppId, d.Host, d.Method, d.RemoteIp, d.Action, d.Score = time.Now().Unix(), "static", "shop.example", "POST", "203.0.113.9", "log", 90
		if err := st.Send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Decision{Decision: d}}); err != nil {
			t.Fatal(err)
		}
	}
	type want struct{ uri, query, preview, body string }
	wants := []want{
		{"/login?code=" + red, "code=" + red, "username=alice&password=" + payload + "&csrf_token=" + red, "username=alice&password=" + payload + "&csrf_token=" + red},
		{"/login?code=" + red, "code=" + red, "username=alice&password=" + red + "&csrf_token=" + red, "username=alice&password=" + red + "&csrf_token=" + red},
		{"/cb?token=eyJhbGciOiJub25lIn0." + red, "token=eyJhbGciOiJub25lIn0." + red, "", `{"refresh_token":"` + red + `","n":1}`},
	}
	for i, w := range wants {
		select {
		case ev := <-sub.Ch:
			if ev.GetUri() != w.uri || ev.GetQueryParams() != w.query || ev.GetBodyPreview() != w.preview || ev.GetRequestBody() != w.body {
				t.Errorf("published %d: uri %q query %q preview %q body %q", i, ev.GetUri(), ev.GetQueryParams(), ev.GetBodyPreview(), ev.GetRequestBody())
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("decision %d not published", i)
		}
	}
	waitUntil(t, "decisions persisted", func() bool {
		n := 0
		for _, b := range env.ins.snapshot() {
			n += len(b)
		}
		return n == len(wants)
	})
	var rows []string
	for _, b := range env.ins.snapshot() {
		for _, r := range b {
			rows = append(rows, r.URI+"|"+r.QueryParams+"|"+r.BodyPreview+"|"+r.RequestBody)
		}
	}
	for i, w := range wants {
		if got, exp := rows[i], w.uri+"|"+w.query+"|"+w.preview+"|"+w.body; got != exp {
			t.Errorf("stored %d:\n got %q\nwant %q", i, got, exp)
		}
	}
}

// An already redacted decision (current agent) passes ingest unchanged, and
// an old agent's URI-keyed login scope still uses the URI as sent.
func TestRedactDecisionAtIngestIdempotent(t *testing.T) {
	const red = domain.DecisionRedactedMarker
	dec := &agentv1.WAFDecisionEvent{
		Uri: "/login?token=" + red, QueryParams: "token=" + red, MatchSource: "header:Authorization",
		RequestHeaders: map[string]string{"Authorization": "Bearer eyJ." + red, "X-Api-Key": red},
	}
	raw := redactDecisionAtIngest(dec)
	if raw != "/login?token="+red || dec.GetUri() != raw || dec.GetQueryParams() != "token="+red ||
		dec.GetRequestHeaders()["Authorization"] != "Bearer eyJ."+red || dec.GetRequestHeaders()["X-Api-Key"] != red {
		t.Fatalf("changed on second redaction: %+v", dec)
	}
	if redactDecisionAtIngest(nil) != "" {
		t.Fatal("nil decision")
	}

	old := &agentv1.WAFDecisionEvent{Uri: "/login?session=abc"}
	rawURI := redactDecisionAtIngest(old)
	if old.GetUri() != "/login?session="+red {
		t.Fatalf("uri = %q", old.GetUri())
	}
	if got := loginUnblockScopeURI("p1", old, rawURI); got != "login:p1:/login?session=abc" {
		t.Fatalf("old-agent login scope = %q", got)
	}
}
