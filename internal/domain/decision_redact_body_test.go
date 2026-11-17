package domain

import (
	"maps"
	"net/url"
	"strings"
	"testing"
)

// Guesses never name a secret
// parameter, an exact source keeps its flagged value except for credential
// checks, and bodies are redacted field by field.

func exactMatch(ms string, categories ...string) MatchEvidence {
	return DecisionMatch(ms, true, categories)
}

// An exact source keeps whatever the engine flagged, including the
// classes LooksLikeAttackPayload does not recognise.
func TestExactSourceKeepsFlaggedValue(t *testing.T) {
	payloads := []string{
		"1 OR 1=1--", "/etc/passwd", "file:///etc/passwd", "http://169.254.169.254/latest/meta-data/",
		"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3Rvcg", ";cat /etc/passwd", "|id",
		"__import__('os').system('id')", "system('id')", "*)(uid=*", `{"$ne":null}`,
	}
	for _, p := range payloads {
		enc := url.QueryEscape(p)
		for _, name := range []string{"code", "password", "access_token"} {
			q := name + "=" + enc + "&api_key=SECRET"
			got := RedactDecisionQuery(q, exactMatch("query:"+name, "RCE"))
			if want := name + "=" + enc + "&api_key=" + red; got != want {
				t.Errorf("exact query:%s: got %q, want %q", name, got, want)
			}
			if g := RedactDecisionQuery(q, GuessedMatch("query:"+name)); strings.Contains(g, enc) {
				t.Errorf("guessed query:%s kept %q", name, g)
			}
		}
		h := RedactDecisionHeaders(map[string]string{"X-Api-Key": p, "X-Auth-Token": "REAL"}, exactMatch("header:X-Api-Key", "LFI"))
		if strings.IndexByte(p, ',') < 0 && (h["X-Api-Key"] != p || h["X-Auth-Token"] != red) {
			t.Errorf("exact header %q: %v", p, h)
		}
		if c := RedactDecisionHeaders(map[string]string{"Cookie": "sid=" + p + "; other_session=S"}, exactMatch("cookie:sid", "SQLi")); strings.IndexByte(p, ';') < 0 && c["Cookie"] != "sid="+p {
			t.Errorf("exact cookie %q: %v", p, c)
		}
	}
}

// Credential checks keep a reduced form only.
func TestExactCredentialVerdictIsReduced(t *testing.T) {
	const jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."
	cases := []struct {
		name, q, ms string
		cats        []string
		want        string
	}{
		{"JWT engine on a token parameter", "token=" + jwt + "&x=1", "query:token", []string{"JWT"}, "token=eyJhbGciOiJub25lIn0." + red + "&x=1"},
		{"entropy anomaly on a password", "password=Zq8%23Lp!v2%25Rt&x=1", "query:password", []string{"Anomaly"}, "password=" + redactedLenPrefix + "16]&x=1"},
		{"non-JWT dotted session value", "sid=s:abc123.sig", "query:sid", []string{"JWT"}, "sid=" + redactedLenPrefix + "12]"},
		{"non-secret parameter is kept", "q=" + jwt, "query:q", []string{"JWT"}, "q=" + jwt},
	}
	for _, c := range cases {
		m := exactMatch(c.ms, c.cats...)
		got := RedactDecisionQuery(c.q, m)
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
		if again := RedactDecisionQuery(got, m); again != got {
			t.Errorf("%s: not idempotent %q -> %q", c.name, got, again)
		}
	}
	h := RedactDecisionHeaders(map[string]string{
		"X-Access-Token": jwt, "Authorization": "Bearer " + jwt,
	}, exactMatch("header:X-Access-Token", "JWT"))
	if h["X-Access-Token"] != "eyJhbGciOiJub25lIn0."+red || h["Authorization"] != "" {
		t.Errorf("JWT header: %v", h)
	}
	a := RedactDecisionHeaders(map[string]string{"Authorization": "Bearer " + jwt}, exactMatch("header:Authorization", "SQLi"))
	if a["Authorization"] != "Bearer eyJhbGciOiJub25lIn0."+red {
		t.Errorf("Authorization is always reduced: %v", a)
	}
	// Bearer value that is not a JWT: no prefix of it is kept.
	b := RedactDecisionHeaders(map[string]string{"Authorization": "Bearer s:abc.sig"}, exactMatch("header:Authorization"))
	if b["Authorization"] != "Bearer "+red {
		t.Errorf("non-JWT bearer: %v", b)
	}
	// Multi-value secret header keeps the comma rule.
	mv := RedactDecisionHeaders(map[string]string{"X-Api-Key": "REAL, <script>"}, exactMatch("header:X-Api-Key", "XSS"))
	if mv["X-Api-Key"] != red+", <script>" {
		t.Errorf("multi-value: %v", mv)
	}
	if !IsCredentialVerdict([]string{"SQLi", "jwt"}) || IsCredentialVerdict([]string{"SQLi"}) || IsCredentialVerdict(nil) {
		t.Error("IsCredentialVerdict")
	}
}

// URL-valued header evidence (Referer) keeps the payload, not the
// credentials, when exact; when guessed it keeps no secret-named value.
func TestURLValuedHeaderEvidence(t *testing.T) {
	ref := "https://a.example/p?access_token=TOK&token=%3Cimg%3E&q=<script>"
	ex := RedactDecisionHeaders(map[string]string{"Referer": ref}, exactMatch("header:Referer"))
	if ex["Referer"] != "https://a.example/p?access_token="+red+"&token=%3Cimg%3E&q=<script>" {
		t.Errorf("exact Referer: %q", ex["Referer"])
	}
	gs := RedactDecisionHeaders(map[string]string{"Referer": ref}, GuessedMatch("header:Referer"))
	if gs["Referer"] != "https://a.example/p?access_token="+red+"&token="+red+"&q=<script>" {
		t.Errorf("guessed Referer: %q", gs["Referer"])
	}
	// Guessed Cookie header: secret-named cookies are redacted even when
	// payload-like.
	c := RedactDecisionHeaders(map[string]string{"Cookie": "session=%3Cscript%3E; pref=<script>"}, GuessedMatch("header:Cookie"))
	if c["Cookie"] != "session="+red+"; pref=<script>" {
		t.Errorf("guessed Cookie: %q", c["Cookie"])
	}
}

// Body fields.
func TestRedactDecisionBody(t *testing.T) {
	none := MatchEvidence{}
	cases := []struct {
		name, body, ct string
		m              MatchEvidence
		want           string
	}{
		{"login form", "username=alice&password=hunter2&remember=1", "form", none,
			"username=alice&password=" + red + "&remember=1"},
		{"form, raw content type, PHP names", "user%5Bpassword%5D=x&user%5Bname%5D=a", "application/x-www-form-urlencoded; charset=utf-8", none,
			"user%5Bpassword%5D=" + red + "&user%5Bname%5D=a"},
		{"form cut mid value", "user=a&password=hunt", "form", none, "user=a&password=" + red},
		{"form, exact field keeps the payload", "user=a&password=__import__('os').system('id')", "form", exactMatch("body:password", "Python"),
			"user=a&password=__import__('os').system('id')"},
		{"form, guessed field keeps nothing", "password=' OR 1=1--", "form", GuessedMatch("body:password"), "password=" + red},
		{"form, hpp", "pin=1234&pin=' OR 1=1--", "form", exactMatch("body:hpp:pin", "SQLi"), "pin=" + red + "&pin=' OR 1=1--"},
		{"form, credential check", "password=Zq8!v2Rt", "form", exactMatch("body:password", "Anomaly"), "password=" + redactedLenPrefix + "8]"},
		{"JSON nested, keys case-insensitive", `{"user":"a","Password":"p1","profile":{"API_KEY":"k","tags":["x"]},"n":1}`, "json", none,
			`{"user":"a","Password":"` + red + `","profile":{"API_KEY":"` + red + `","tags":["x"]},"n":1}`},
		{"JSON secret container", `{"credentials":{"user":"a","pass":"b"},"tokens":["t1","t2"],"pin":1234,"otp":null}`, "application/json", none,
			`{"credentials":{"user":"` + red + `","pass":"` + red + `"},"tokens":["` + red + `","` + red + `"],"pin":"` + red + `","otp":null}`},
		{"JSON exact key keeps the value", `{"username":"a","password":{"$ne":null},"token":"T"}`, "json", exactMatch("body.json:password", "NoSQLi"),
			`{"username":"a","password":{"$ne":null},"token":"` + red + `"}`},
		{"JSON exact string key", `{"password":"' OR 1=1--","session":"S"}`, "json", exactMatch("body.json:password", "SQLi"),
			`{"password":"' OR 1=1--","session":"` + red + `"}`},
		{"JSON exact key, JWT check", `{"id_token":"eyJhbGciOiJub25lIn0.e30.","x":1}`, "json", exactMatch("body.json:id_token", "JWT"),
			`{"id_token":"eyJhbGciOiJub25lIn0.` + red + `","x":1}`},
		{"JSON cut inside a secret string", `{"user":"a","password":"hunt`, "json", none, `{"user":"a","password":"` + red + `"`},
		{"JSON escaped quotes", `{"password":"a\"b","q":"x\"y"}`, "json", none, `{"password":"` + red + `","q":"x\"y"}`},
		{"JSON escaped key", `{"password":"x"}`, "json", none, `{"password":"` + red + `"}`},
		{"JSON sniffed without content type", ` {"secret":"s"}`, "", none, ` {"secret":"` + red + `"}`},
		{"multipart summary (agent preview)", "user=a&password=hunter2&avatar=[file:a.png]", "multipart", none,
			"user=a&password=" + red + "&avatar=[file:a.png]"},
		{"raw multipart", "--XB\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nalice\r\n--XB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--XB\r\nContent-Disposition: form-data; name=\"token\"; filename=\"t.txt\"\r\n\r\nfiledata\r\n--XB--\r\n",
			"multipart/form-data; boundary=XB", none,
			"--XB\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nalice\r\n--XB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n" + red + "\r\n--XB\r\nContent-Disposition: form-data; name=\"token\"; filename=\"t.txt\"\r\n\r\nfiledata\r\n--XB--\r\n"},
		{"raw multipart cut in a secret part", "--XB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunt", "multipart", none,
			"--XB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n" + red},
		{"raw multipart exact field", "--XB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n|id\r\n--XB--", "multipart/form-data; boundary=XB", exactMatch("body:password", "RCE"),
			"--XB\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n|id\r\n--XB--"},
		{"XML is left as is", "<login><password>x</password></login>", "xml", none, "<login><password>x</password></login>"},
		{"plain text without '='", "hello password", "text", none, "hello password"},
		{"no secret: unchanged", `{"q":"<script>","page":2}`, "json", none, `{"q":"<script>","page":2}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := RedactDecisionBody(c.body, c.ct, c.m)
			if got != c.want {
				t.Fatalf("got  %q\nwant %q", got, c.want)
			}
			if again := RedactDecisionBody(got, c.ct, c.m); again != got {
				t.Fatalf("not idempotent: %q -> %q", got, again)
			}
		})
	}
}

func TestRedactDecisionBodyMalformedNeverPanics(t *testing.T) {
	inputs := []string{
		"", "{", "}", "[", `"`, `{"`, `{"password`, `{"password"`, `{"password":`, `{"password":"`, `{"password":"\`,
		`{"a":[[[[`, `]]]]}}}`, `{password:"x"}`, "--", "--b\r\n", "--b\r\nContent-Disposition: form-data; name=\"pin\"",
		"=", "&&&", "password=", "%zz=%zz", "\x00\xff{\"token\":\x00}",
	}
	for _, in := range inputs {
		for _, ct := range []string{"json", "form", "multipart", "multipart/form-data; boundary=b", ""} {
			for _, m := range []MatchEvidence{{}, exactMatch("body:pin"), exactMatch("body.json:password", "JWT")} {
				_ = RedactDecisionBody(in, ct, m)
			}
		}
	}
}

// The control plane redacts again what a current agent sent: unchanged.
func TestRedactDecisionHeadersQueryIdempotentExact(t *testing.T) {
	m := exactMatch("header:X-Api-Key", "Anomaly")
	h := RedactDecisionHeaders(map[string]string{"X-Api-Key": "Zq8#Lp!v2%Rt"}, m)
	if h["X-Api-Key"] != redactedLenPrefix+"12]" {
		t.Fatalf("got %v", h)
	}
	if again := RedactDecisionHeaders(maps.Clone(h), m); !maps.Equal(h, again) {
		t.Fatalf("not idempotent %v vs %v", h, again)
	}
}

func FuzzRedactDecisionBody(f *testing.F) {
	f.Add(`{"password":"x","a":[1,{"token":"y"}]}`, "json", "body.json:password", true)
	f.Add("user=a&password=b", "form", "body:password", false)
	f.Add("--b\r\nContent-Disposition: form-data; name=\"pin\"\r\n\r\n1\r\n--b--", "multipart", "", false)
	f.Fuzz(func(t *testing.T, body, ct, ms string, exact bool) {
		m := MatchEvidence{Source: ms, Exact: exact}
		got := RedactDecisionBody(body, ct, m)
		if again := RedactDecisionBody(got, ct, m); again != got {
			t.Fatalf("not idempotent: %q -> %q -> %q", body, got, again)
		}
	})
}

func BenchmarkIsSecretFieldName(b *testing.B) {
	names := []string{"name", "qty", "note", "username", "X-Forwarded-For", "Accept-Language", "password", "fieldxxx"}
	b.ReportAllocs()
	for b.Loop() {
		for _, n := range names {
			IsSecretFieldName(n)
		}
	}
}

func benchBody(n int) (form, json string) {
	var fb, jb strings.Builder
	jb.WriteString(`{"items":[`)
	for i := 0; fb.Len() < n; i++ {
		if i > 0 {
			fb.WriteByte('&')
			jb.WriteByte(',')
		}
		fb.WriteString("field" + strings.Repeat("x", i%7) + "=value+with+some+text")
		jb.WriteString(`{"name":"item","qty":3,"note":"some text here"}`)
	}
	jb.WriteString(`],"password":"hunter2"}`)
	return fb.String() + "&password=hunter2", jb.String()
}

func BenchmarkRedactDecisionBodyForm4K(b *testing.B) {
	form, _ := benchBody(4096)
	b.ReportAllocs()
	b.SetBytes(int64(len(form)))
	for b.Loop() {
		RedactDecisionBody(form, "form", MatchEvidence{})
	}
}

func BenchmarkRedactDecisionBodyJSON4K(b *testing.B) {
	_, js := benchBody(4096)
	b.ReportAllocs()
	b.SetBytes(int64(len(js)))
	for b.Loop() {
		RedactDecisionBody(js, "json", MatchEvidence{})
	}
}

func BenchmarkRedactDecisionBodyJSONClean512(b *testing.B) {
	_, js := benchBody(512)
	js = strings.Replace(js, `"password"`, `"comment"`, 1)
	b.ReportAllocs()
	for b.Loop() {
		RedactDecisionBody(js, "json", MatchEvidence{})
	}
}
