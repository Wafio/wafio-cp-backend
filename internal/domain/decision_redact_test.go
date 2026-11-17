package domain

import (
	"maps"
	"testing"
)

const red = DecisionRedactedMarker

func TestIsSecretFieldName(t *testing.T) {
	secret := []string{
		// exact names from the security review
		"X-API-Key", "x-api-key", "X-Auth-Token", "X-CSRF-Token", "X-XSRF-TOKEN",
		"X-Access-Token", "Api-Key", "X-Amz-Security-Token", "X-Goog-Api-Key",
		"Authorization", "Proxy-Authorization", "X-Session-Id", "X-Refresh-Token",
		"Private-Token", "X-Vault-Token", "X-Hasura-Admin-Secret", "Ocp-Apim-Subscription-Key",
		"X-Functions-Key", "X-Hub-Signature-256", "Stripe-Signature", "X-Shopify-Hmac-Sha256",
		"X-CSRFToken", "X-Client-Secret", "X-Auth", "auth",
		// query parameters, camelCase and snake_case
		"api_key", "apiKey", "apikey", "token", "access_token", "accessToken", "id_token",
		"refresh_token", "password", "new_password", "passwd", "pwd", "user_pwd", "pass",
		"client_secret", "clientSecret", "session", "sessionId", "PHPSESSID", "JSESSIONID",
		"connect.sid", "sid", "otp", "totp", "key", "sig", "ticket", "jwt",
		"X-Amz-Signature", "X-Amz-Credential", "X-Goog-Signature", "aws_secret_access_key",
		"user[password]", "data.token", " Token ",
		// review 2026-10-17: OAuth code, SAML messages, PINs and passcodes
		"code", "CODE", "SAMLResponse", "SAMLRequest", "passcode", "user_passcode", "pin", "card_pin",
		"auth_code", "authCode",
	}
	for _, n := range secret {
		if !IsSecretFieldName(n) {
			t.Errorf("IsSecretFieldName(%q) = false, want true", n)
		}
	}
	// Common headers and parameters that carry attack evidence must stay readable.
	plain := []string{
		"", "Host", "User-Agent", "Referer", "Origin", "Accept", "Accept-Encoding",
		"Content-Type", "Content-Length", "X-Forwarded-For", "X-Real-IP", "X-Request-ID",
		"Cache-Control", "Sec-WebSocket-Key", "Sec-Fetch-Mode", "Keep-Alive", "Traceparent",
		"X-Original-URL", "If-None-Match", "Upgrade-Insecure-Requests", "X-Amz-Date",
		"X-Amz-Content-Sha256", "X-Auth-Request-Redirect", "Author", "Authority",
		"id", "q", "search", "page", "redirect", "url", "next", "file", "cmd",
		"country_code", "error_code", "zip-code", "pinned", "spin", "shipping",
		"user", "username", "email", "bypass", "passenger", "keyword", "monkey", "x-keyboard",
	}
	for _, n := range plain {
		if IsSecretFieldName(n) {
			t.Errorf("IsSecretFieldName(%q) = true, want false", n)
		}
	}
}

func TestParseMatchSource(t *testing.T) {
	cases := []struct{ in, kind, name string }{
		{"header:X-Api-Key", evidenceHeader, "X-Api-Key"},
		{"HEADER:Cookie", evidenceHeader, "Cookie"},
		{"REQUEST_HEADERS:x-auth-token", evidenceHeader, "x-auth-token"},
		{"query:token", evidenceQuery, "token"},
		{"query:hpp:token", evidenceQuery, "token"},
		{"query:name:token", evidenceQueryName, "token"},
		{"ARGS_GET:api_key", evidenceQuery, "api_key"},
		{"ARGS:api_key", evidenceQuery, "api_key"},
		{"cookie:session", evidenceCookie, "session"},
		{"REQUEST_COOKIES:sid", evidenceCookie, "sid"},
		{"query", evidenceNone, ""},
		{"query:", evidenceNone, ""},
		{"body", evidenceNone, ""},
		{"body:password", evidenceBody, "password"},
		{"body.json:password", evidenceBody, "password"},
		{"body:hpp:pin", evidenceBody, "pin"},
		{"body:f:filename", evidenceBody, "f"},
		{"body:name:password", evidenceNone, ""},
		{"body.json", evidenceNone, ""},
		{"path:/login", evidenceNone, ""},
		{"ws:handshake", evidenceNone, ""},
		{":x", evidenceNone, ""},
		{"", evidenceNone, ""},
	}
	for _, c := range cases {
		k, n := parseMatchSource(c.in)
		if k != c.kind || n != c.name {
			t.Errorf("parseMatchSource(%q) = (%q,%q), want (%q,%q)", c.in, k, n, c.kind, c.name)
		}
	}
}

func TestRedactDecisionHeaders(t *testing.T) {
	jwt := "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.c2ln"
	base := func() map[string]string {
		return map[string]string{
			"User-Agent":          "sqlmap/1.7",
			"X-Api-Key":           "sk_live_123",
			"x-csrf-token":        "csrf-abc",
			"Authorization":       jwt,
			"Proxy-Authorization": "Basic dXNlcjpwYXNz",
			"Cookie":              "sid=s3cr3t; theme=dark; q=' OR 1=1--",
			"Set-Cookie":          "a=b",
			"Referer":             "https://shop.example/cb?access_token=abc&page=2",
			"X-Forwarded-For":     "203.0.113.9",
		}
	}
	cases := []struct {
		name, ms string
		want     map[string]string
	}{
		{"no match source", "", map[string]string{
			"User-Agent": "sqlmap/1.7", "X-Api-Key": red, "x-csrf-token": red,
			"Referer": "https://shop.example/cb?access_token=" + red + "&page=2", "X-Forwarded-For": "203.0.113.9",
		}},
		{"match source names a secret header, its value is no payload", "header:x-api-key", map[string]string{
			"User-Agent": "sqlmap/1.7", "X-Api-Key": red, "x-csrf-token": red,
			"Referer": "https://shop.example/cb?access_token=" + red + "&page=2", "X-Forwarded-For": "203.0.113.9",
		}},
		{"a matched-variable name of an older agent names a secret header, its value is no payload", "REQUEST_HEADERS:X-CSRF-Token", map[string]string{
			"User-Agent": "sqlmap/1.7", "X-Api-Key": red, "x-csrf-token": red,
			"Referer": "https://shop.example/cb?access_token=" + red + "&page=2", "X-Forwarded-For": "203.0.113.9",
		}},
		{"Referer named still has its secret parameters redacted", "header:Referer", map[string]string{
			"User-Agent": "sqlmap/1.7", "X-Api-Key": red, "x-csrf-token": red,
			"Referer": "https://shop.example/cb?access_token=" + red + "&page=2", "X-Forwarded-For": "203.0.113.9",
		}},
		{"Authorization named is reduced to scheme + JWT header", "header:Authorization", map[string]string{
			"User-Agent": "sqlmap/1.7", "X-Api-Key": red, "x-csrf-token": red,
			"Authorization": "Bearer eyJhbGciOiJub25lIn0." + red,
			"Referer":       "https://shop.example/cb?access_token=" + red + "&page=2", "X-Forwarded-For": "203.0.113.9",
		}},
		{"Proxy-Authorization named keeps the scheme only", "header:Proxy-Authorization", map[string]string{
			"User-Agent": "sqlmap/1.7", "X-Api-Key": red, "x-csrf-token": red,
			"Proxy-Authorization": "Basic " + red,
			"Referer":             "https://shop.example/cb?access_token=" + red + "&page=2", "X-Forwarded-For": "203.0.113.9",
		}},
		{"one cookie named keeps only its pair", "cookie:q", map[string]string{
			"User-Agent": "sqlmap/1.7", "X-Api-Key": red, "x-csrf-token": red,
			"Cookie":  "q=' OR 1=1--",
			"Referer": "https://shop.example/cb?access_token=" + red + "&page=2", "X-Forwarded-For": "203.0.113.9",
		}},
		{"Cookie header named keeps suspicious values only", "header:Cookie", map[string]string{
			"User-Agent": "sqlmap/1.7", "X-Api-Key": red, "x-csrf-token": red,
			"Cookie":  "sid=" + red + "; theme=" + red + "; q=' OR 1=1--",
			"Referer": "https://shop.example/cb?access_token=" + red + "&page=2", "X-Forwarded-For": "203.0.113.9",
		}},
		{"named cookie absent drops the header", "cookie:nope", map[string]string{
			"User-Agent": "sqlmap/1.7", "X-Api-Key": red, "x-csrf-token": red,
			"Referer": "https://shop.example/cb?access_token=" + red + "&page=2", "X-Forwarded-For": "203.0.113.9",
		}},
		{"query match source does not unredact headers", "query:X-Api-Key", map[string]string{
			"User-Agent": "sqlmap/1.7", "X-Api-Key": red, "x-csrf-token": red,
			"Referer": "https://shop.example/cb?access_token=" + red + "&page=2", "X-Forwarded-For": "203.0.113.9",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := RedactDecisionHeaders(base(), GuessedMatch(c.ms))
			if !maps.Equal(got, c.want) {
				t.Fatalf("got  %v\nwant %v", got, c.want)
			}
			// Idempotent: the control plane redacts a current agent's output again.
			again := RedactDecisionHeaders(maps.Clone(got), GuessedMatch(c.ms))
			if !maps.Equal(again, got) {
				t.Fatalf("not idempotent:\nonce  %v\ntwice %v", got, again)
			}
		})
	}
}

func TestRedactDecisionHeadersOddInputs(t *testing.T) {
	if got := RedactDecisionHeaders(nil, GuessedMatch("header:x")); got != nil {
		t.Fatalf("nil map = %v", got)
	}
	if got := RedactDecisionHeaders(map[string]string{"Authorization": "x", "Cookie": "a=b"}, GuessedMatch("")); got != nil {
		t.Fatalf("all dropped = %v, want nil", got)
	}
	for _, v := range []string{"", " ", "Bearer", "Bearer ", "Bearer .", "Bearer a.b.c", "Basic", "x y z", "\x00\xff"} {
		h := map[string]string{"Authorization": v}
		got := RedactDecisionHeaders(h, GuessedMatch("header:Authorization"))
		again := RedactDecisionHeaders(maps.Clone(got), GuessedMatch("header:Authorization"))
		if !maps.Equal(got, again) {
			t.Errorf("Authorization %q: not idempotent %v vs %v", v, got, again)
		}
		if a := got["Authorization"]; a != "" && a != red && a != "Bearer a."+red && a != "Bearer "+red && a != "Basic "+red && a != "x "+red {
			t.Errorf("Authorization %q reduced to %q", v, a)
		}
	}
	for _, v := range []string{"", ";", ";;=;", "=", "a", "a=", "=b", "a=b;;c=d", "<script>"} {
		for _, ms := range []string{"header:Cookie", "cookie:a", "cookie:"} {
			got := RedactDecisionHeaders(map[string]string{"Cookie": v}, GuessedMatch(ms))
			again := RedactDecisionHeaders(maps.Clone(got), GuessedMatch(ms))
			if !maps.Equal(got, again) {
				t.Errorf("Cookie %q ms %q: not idempotent %v vs %v", v, ms, got, again)
			}
		}
	}
}

func TestRedactDecisionQuery(t *testing.T) {
	cases := []struct {
		q, ms string
		exact bool
		want  string
	}{
		{"", "", false, ""},
		{"id=1", "", false, "id=1"},
		{"api_key=abc&id=1", "", false, "api_key=" + red + "&id=1"},
		{"API_KEY=abc", "", false, "API_KEY=" + red},
		{"accessToken=abc&q=x", "query:q", true, "accessToken=" + red + "&q=x"},
		// exact: the engine flagged that value, whatever it looks like
		{"token=' OR 1=1--&x=1", "query:token", true, "token=' OR 1=1--&x=1"},
		{"token=a", "ARGS_GET:token", true, "token=a"},
		{"token=$(id)", "ARGS_GET:token", true, "token=$(id)"},
		// guessed: nothing is exempt, payload or not
		{"token=' OR 1=1--&x=1", "query:token", false, "token=" + red + "&x=1"},
		{"token=a", "ARGS_GET:token", false, "token=" + red},
		{"token=$(id)", "ARGS_GET:token", false, "token=" + red},
		// several values: only payload-like ones
		{"token=a&token=b", "query:hpp:token", true, "token=" + red + "&token=" + red},
		{"token=a&token=%3Cscript%3E", "query:hpp:token", true, "token=" + red + "&token=%3Cscript%3E"},
		{"token=a&token=%3Cscript%3E", "query:token", true, "token=" + red + "&token=%3Cscript%3E"},
		{"token=a&token=%3Cscript%3E", "query:hpp:token", false, "token=" + red + "&token=" + red},
		{"token=a", "query:name:token", true, "token=" + red},
		{"token=a", "query", true, "token=" + red},
		{"token=a", "body", true, "token=" + red},
		{"token=a", "body:token", true, "token=" + red},
		{"access%5Ftoken=a&b", "", false, "access%5Ftoken=" + red + "&b"},
		{"user%5Bpassword%5D=a", "", false, "user%5Bpassword%5D=" + red},
		{"token=&password", "", false, "token=&password"},
		{"&&=&token==x", "", false, "&&=&token=" + red},
		{"%zz=1&pwd=2", "", false, "%zz=1&pwd=" + red},
		{"X-Amz-Credential=AKIA%2F20261017&X-Amz-Signature=abc&X-Amz-Date=1", "", false, "X-Amz-Credential=" + red + "&X-Amz-Signature=" + red + "&X-Amz-Date=1"},
	}
	for _, c := range cases {
		m := MatchEvidence{Source: c.ms, Exact: c.exact}
		got := RedactDecisionQuery(c.q, m)
		if got != c.want {
			t.Errorf("RedactDecisionQuery(%q,%q,exact=%v) = %q, want %q", c.q, c.ms, c.exact, got, c.want)
		}
		if again := RedactDecisionQuery(got, m); again != got {
			t.Errorf("not idempotent: %q -> %q", got, again)
		}
	}
}

func TestRedactDecisionURI(t *testing.T) {
	cases := []struct{ uri, ms, want string }{
		{"", "", ""},
		{"/a", "", "/a"},
		{"/a?", "", "/a?"},
		{"/login?password=hunter2&next=/", "", "/login?password=" + red + "&next=/"},
		{"/login?password=hunter2", "query:password", "/login?password=" + red},
		{"/login?password='+or+1=1--", "query:password", "/login?password=" + red}, // guessed: never exempt
		{"/p/token=x?id=1", "", "/p/token=x?id=1"},
		{"https://h/x?sig=abc", "", "https://h/x?sig=" + red},
	}
	for _, c := range cases {
		if got := RedactDecisionURI(c.uri, GuessedMatch(c.ms)); got != c.want {
			t.Errorf("RedactDecisionURI(%q,%q) = %q, want %q", c.uri, c.ms, got, c.want)
		}
	}
}

func BenchmarkRedactDecisionHeaders(b *testing.B) {
	src := map[string]string{
		"Host": "shop.example", "User-Agent": "Mozilla/5.0", "Accept": "text/html", "Accept-Encoding": "gzip",
		"Accept-Language": "en", "Connection": "keep-alive", "Cookie": "sid=1; a=2", "Referer": "https://shop.example/?q=1",
		"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "same-origin", "X-Forwarded-For": "203.0.113.9",
		"X-Request-Id": "abc", "Content-Type": "application/json", "Content-Length": "12", "X-Api-Key": "k",
	}
	b.ReportAllocs()
	for b.Loop() {
		RedactDecisionHeaders(maps.Clone(src), GuessedMatch("query:q"))
	}
}

func FuzzRedactDecision(f *testing.F) {
	f.Add("a=b&token=c", "header:Cookie", "sid=1; x=<script>", "Bearer a.b.c")
	f.Add("", "", "", "")
	f.Fuzz(func(t *testing.T, q, ms, cookie, auth string) {
		for _, m := range []MatchEvidence{GuessedMatch(ms), {Source: ms, Exact: true}, {Source: ms, Exact: true, Credential: true}} {
			r := RedactDecisionQuery(q, m)
			if RedactDecisionQuery(r, m) != r {
				t.Fatalf("query not idempotent: %q %+v", q, m)
			}
			h := RedactDecisionHeaders(map[string]string{"Cookie": cookie, "Authorization": auth, "X-Api-Key": q}, m)
			if again := RedactDecisionHeaders(maps.Clone(h), m); !maps.Equal(h, again) {
				t.Fatalf("headers not idempotent: %v vs %v", h, again)
			}
			_ = RedactDecisionURI("/x?"+q, m)
			for _, ct := range []string{"json", "form", "multipart", ""} {
				b := RedactDecisionBody(q, ct, m)
				if again := RedactDecisionBody(b, ct, m); again != b {
					t.Fatalf("body not idempotent (%s): %q -> %q -> %q", ct, q, b, again)
				}
			}
		}
	})
}
