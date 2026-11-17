package domain

import (
	"maps"
	"testing"
)

// A guessed or exact match
// source never keeps a credential that does not look like a payload; URL
// evidence, multi-value headers, cookies, ';' parameters and further names.

func TestLooksLikeAttackPayload(t *testing.T) {
	payload := []string{
		"' OR 1=1--", "1' UNION SELECT 1,2--", "<script>alert(1)</script>", "%3Cscript%3E",
		"${jndi:ldap://x/a}", "{{7*7}}", "$(id)", "`id`", "../../etc/passwd", "..%2F..%2Fetc%2Fpasswd",
		`..\..\win.ini`, "a%00b", "javascript:alert(1)", "1;sleep(5)", "x%2527",
	}
	for _, v := range payload {
		if !LooksLikeAttackPayload(v) {
			t.Errorf("LooksLikeAttackPayload(%q) = false, want true", v)
		}
	}
	notPayload := []string{
		"", " ", DecisionRedactedMarker, "SECRET123", "sk_live_123", "csrf-abc", "hunter2",
		// token-shaped values carrying weak markers by chance
		"aGVsbG8--d29ybGQ", `"YWJjZGVm=="`, "YWJjZGVm==", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln",
		"0123456789abcdef", "abc%2Bdef%3D%3D", "s%3AeyJh--b2s.sig", "a/b+c==",
	}
	for _, v := range notPayload {
		if LooksLikeAttackPayload(v) {
			t.Errorf("LooksLikeAttackPayload(%q) = true, want false", v)
		}
	}
}

// Evidence is kept element by element; URL evidence keeps its
// payload but not its credentials.
func TestRedactDecisionHeadersEvidenceScope(t *testing.T) {
	cases := []struct {
		name, ms string
		in, want map[string]string
	}{
		{"multi-value secret header keeps the payload element", "header:X-Api-Key",
			map[string]string{"X-Api-Key": "<script>, REALSECRET"},
			map[string]string{"X-Api-Key": "<script>, " + red}},
		{"secret header without payload element", "header:X-Api-Key",
			map[string]string{"X-Api-Key": "a, b"},
			map[string]string{"X-Api-Key": red}},
		{"payload in a secret header is kept", "header:X-Auth-Token",
			map[string]string{"X-Auth-Token": "' OR 1=1--"},
			map[string]string{"X-Auth-Token": "' OR 1=1--"}},
		{"Referer evidence keeps the payload param, not the token", "header:Referer",
			map[string]string{"Referer": "https://a.example/p;jsessionid=ABC123?access_token=TOK&q=<script>&token=%3Cimg%3E"},
			map[string]string{"Referer": "https://a.example/p;jsessionid=" + red + "?access_token=" + red + "&q=<script>&token=%3Cimg%3E"}},
		{"non-secret evidence header keeps commas", "header:User-Agent",
			map[string]string{"User-Agent": "x, y' OR 1=1"},
			map[string]string{"User-Agent": "x, y' OR 1=1"}},
		{"exactly named session cookie keeps its flagged value", "cookie:session",
			map[string]string{"Cookie": "session=YWJjZGVm--Zw; theme=dark"},
			map[string]string{"Cookie": "session=YWJjZGVm--Zw"}},
		{"session cookie named twice keeps payload-like values only", "cookie:session",
			map[string]string{"Cookie": "session=YWJjZGVm--Zw; session=' OR 1=1--"},
			map[string]string{"Cookie": "session=" + red + "; session=' OR 1=1--"}},
		{"named session cookie with payload", "cookie:session",
			map[string]string{"Cookie": "session=' OR 1=1--"},
			map[string]string{"Cookie": "session=' OR 1=1--"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := RedactDecisionHeaders(maps.Clone(c.in), MatchEvidence{Source: c.ms, Exact: true})
			if !maps.Equal(got, c.want) {
				t.Fatalf("got  %v\nwant %v", got, c.want)
			}
			if again := RedactDecisionHeaders(maps.Clone(got), MatchEvidence{Source: c.ms, Exact: true}); !maps.Equal(again, got) {
				t.Fatalf("not idempotent: %v vs %v", got, again)
			}
		})
	}
}

// Token-shaped cookie values are redacted even with "--" or quotes.
func TestRedactCookieToSuspiciousTokens(t *testing.T) {
	cases := []struct{ in, want string }{
		{`session="YWJjZGVm=="`, "session=" + red},
		{"sid=aGVsbG8--d29ybGQtdG9rZW4tdmFsdWUtMTIzNDU2", "sid=" + red},
		{"a=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "a=" + red},
		{"t=abc%2Bdef%3D", "t=" + red},
		{"q=' OR 1=1--", "q=' OR 1=1--"},
		{"q=<script>", "q=<script>"},
		{"p=../../etc/passwd", "p=../../etc/passwd"},
	}
	for _, c := range cases {
		if got := RedactCookieToSuspicious(c.in); got != c.want {
			t.Errorf("RedactCookieToSuspicious(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ';' separators, path parameters, OAuth/SAML/PIN names.
func TestRedactDecisionURISemicolonsAndNames(t *testing.T) {
	cases := []struct{ uri, ms, want string }{
		{"/a?x=1;token=S2", "", "/a?x=1;token=" + red},
		{"/a?x=1;token=S2&y=2", "", "/a?x=1;token=" + red + "&y=2"},
		{"/app;jsessionid=ABCDEF/x?id=1", "", "/app;jsessionid=" + red + "/x?id=1"},
		{"/app;jsessionid=ABCDEF", "", "/app;jsessionid=" + red},
		{"/app;jsessionid=%3Cscript%3E", "", "/app;jsessionid=%3Cscript%3E"},
		{"/a;v=1/b;x", "", "/a;v=1/b;x"},
		{"/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz", "", "/cb?code=" + red + "&state=xyz"},
		{"/cb?code=1'+OR+1=1--", "query:code", "/cb?code=" + red}, // guessed
		{"/acs?SAMLResponse=PHNhbWw%2B&RelayState=r", "", "/acs?SAMLResponse=" + red + "&RelayState=r"},
		{"/v?pin=1234&passcode=9876", "", "/v?pin=" + red + "&passcode=" + red},
	}
	for _, c := range cases {
		got := RedactDecisionURI(c.uri, GuessedMatch(c.ms))
		if got != c.want {
			t.Errorf("RedactDecisionURI(%q,%q) = %q, want %q", c.uri, c.ms, got, c.want)
		}
		if again := RedactDecisionURI(got, GuessedMatch(c.ms)); again != got {
			t.Errorf("not idempotent: %q -> %q", got, again)
		}
	}
	if got := RedactDecisionQuery("x=1;token=S2", GuessedMatch("")); got != "x=1;token="+red {
		t.Errorf("query ';' = %q", got)
	}
}

func BenchmarkRedactDecisionURI(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		RedactDecisionURI("/search?q=shoes&page=2&sort=price;lang=en", GuessedMatch("query:q"))
	}
}
