package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

func TestUnquoteJSONStringMatchesEncodingJSON(t *testing.T) {
	for _, s := range []string{
		"",
		"plain",
		"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMG\r\n-----END PRIVATE KEY-----\n",
		"tab\there \"quoted\" back\\slash /slash",
		"<html> &     \x00 \x1f \x7f",
		"café 世界 \U0001F600",
		"\b\f",
	} {
		quoted, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := unquoteJSONString(quoted)
		if !ok || string(got) != s {
			t.Errorf("unquote(%s) = %q, %v, want %q", quoted, got, ok, s)
		}
	}
	// Forms encoding/json would not write but accepts: escaped slash and upper-case hex, an escaped
	// surrogate pair, and a lone half, which becomes the replacement character.
	for in, want := range map[string]string{
		`"a\/b"`:    "a/b",
		`"é"`:       "é",
		`"😀"`:       "\U0001F600",
		`"\ud83d"`:  "�",
		`"\ude00x"`: "�x",
		`"\ud83dA"`: "�A",
		`"A😀"`:      "A\U0001F600",
	} {
		if got, ok := unquoteJSONString([]byte(in)); !ok || string(got) != want {
			t.Errorf("unquote(%s) = %q, %v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{`abc`, `"abc`, `abc"`, `"`, `"\x41"`, `"\u12"`, `"\u12G4"`, `"abc\"`, `5`, `[]`, `{}`} {
		if got, ok := unquoteJSONString([]byte(in)); ok || got != nil {
			t.Errorf("unquote(%s) = %q, %v, want a refusal", in, got, ok)
		}
	}
	for _, in := range []string{"", "null"} {
		if got, ok := unquoteJSONString([]byte(in)); !ok || len(got) != 0 {
			t.Errorf("unquote(%q) = %q, %v, want no bytes", in, got, ok)
		}
	}
}

func TestPublicAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"203.0.113.10": true, "198.51.100.7": true, "8.8.8.8": true, "2001:db8::1": true, "2606:4700::1111": true,
		"10.0.0.5": false, "172.16.0.1": false, "192.168.1.1": false, "100.64.0.1": false, "100.127.255.255": false,
		"127.0.0.1": false, "169.254.1.1": false, "0.0.0.0": false, "224.0.0.1": false,
		"::1": false, "fe80::1": false, "fd00::1": false, "::": false,
	} {
		if got := publicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("publicAddr(%s) = %v, want %v", addr, got, want)
		}
	}
	if !publicAddr(netip.MustParseAddr("100.128.0.1")) {
		t.Error("100.128.0.1 is outside 100.64.0.0/10 and public")
	}
}

type tlsFakeResolver struct {
	answers map[string][]netip.Addr
	errs    map[string]error
	calls   atomic.Int32
	// block makes a lookup wait for its context, as a name server that never answers does.
	block bool
}

func (r *tlsFakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r.calls.Add(1)
	if network != "ip" {
		return nil, fmt.Errorf("network %q", network)
	}
	if r.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return r.answers[host], r.errs[host]
}

func addrs(list ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(list))
	for _, s := range list {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func TestDNSMismatches(t *testing.T) {
	known := addrs("203.0.113.10")
	many := make([]string, 0, 12)
	for i := 1; i <= 12; i++ {
		many = append(many, fmt.Sprintf("198.51.100.%d", 100-i))
	}
	r := &tlsFakeResolver{
		answers: map[string][]netip.Addr{
			"ok.example.com":      addrs("203.0.113.10"),
			"mapped.example.com":  addrs("::ffff:203.0.113.10"),
			"either.example.com":  addrs("198.51.100.7", "203.0.113.10"),
			"wrong.example.com":   addrs("198.51.100.7", "198.51.100.7", "2001:db8::5"),
			"private.example.com": addrs("10.0.0.9"),
			"many.example.com":    addrs(many...),
			"empty.example.com":   nil,
		},
		errs: map[string]error{"nxdomain.example.com": errors.New("no such host")},
	}
	hosts := []string{"ok.example.com", "mapped.example.com", "either.example.com", "wrong.example.com", "private.example.com",
		"many.example.com", "empty.example.com", "nxdomain.example.com", "unknown.example.com"}
	got := dnsMismatches(context.Background(), r, hosts, known)

	byHost := map[string]tlsWarning{}
	var order []string
	for _, w := range got {
		if w.Code != tlsWarnDNSMismatch || !slices.Equal(w.AgentAddresses, []string{"203.0.113.10"}) {
			t.Errorf("warning = %+v", w)
		}
		byHost[w.Host] = w
		order = append(order, w.Host)
	}
	// A name that resolves to nothing public, or not at all, is silent: both look the same.
	if want := []string{"wrong.example.com", "many.example.com"}; !slices.Equal(order, want) {
		t.Fatalf("warned hosts %v, want %v (in the order of the hosts)", order, want)
	}
	if res := byHost["wrong.example.com"].Resolved; !slices.Equal(res, []string{"198.51.100.7", "2001:db8::5"}) {
		t.Errorf("resolved = %v, want the addresses sorted and without repeats", res)
	}
	if res := byHost["many.example.com"].Resolved; len(res) != tlsResolvedShown {
		t.Errorf("resolved lists %d addresses, want at most %d", len(res), tlsResolvedShown)
	}
}

// A save looks up at most tlsDNSMaxHosts names; the others are not checked.
func TestDNSMismatchesStopAtTheCap(t *testing.T) {
	r := &tlsFakeResolver{answers: map[string][]netip.Addr{}}
	hosts := make([]string, 15)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%02d.example.com", i)
		r.answers[hosts[i]] = addrs("198.51.100.7")
	}
	got := dnsMismatches(context.Background(), r, hosts, addrs("203.0.113.10"))
	if n := int(r.calls.Load()); n != tlsDNSMaxHosts {
		t.Errorf("%d lookups, want %d", n, tlsDNSMaxHosts)
	}
	if len(got) != tlsDNSMaxHosts || got[0].Host != "h00.example.com" || got[len(got)-1].Host != "h09.example.com" {
		t.Errorf("warnings for %d hosts, want the first %d: %+v", len(got), tlsDNSMaxHosts, got)
	}
}

// A save asks about every host on a switch to gateway and about the added ones afterwards.
func TestDNSCandidates(t *testing.T) {
	proxy := repository.AppTLS{Mode: domain.TLSModeProxy, Hosts: []string{"a.example.com"}}
	gw := func(hosts ...string) repository.AppTLS {
		return repository.AppTLS{Mode: domain.TLSModeGateway, Hosts: hosts}
	}
	for name, c := range map[string]struct {
		before, after repository.AppTLS
		want          []string
	}{
		"switch to gateway":     {proxy, gw("a.example.com", "b.example.com"), []string{"a.example.com", "b.example.com"}},
		"unchanged hosts":       {gw("a.example.com"), gw("a.example.com"), nil},
		"a host added":          {gw("a.example.com"), gw("a.example.com", "b.example.com"), []string{"b.example.com"}},
		"a host removed":        {gw("a.example.com", "b.example.com"), gw("a.example.com"), nil},
		"a host swapped":        {gw("a.example.com"), gw("b.example.com"), []string{"b.example.com"}},
		"leaving gateway":       {gw("a.example.com"), proxy, nil},
		"a draft in proxy mode": {proxy, repository.AppTLS{Mode: domain.TLSModeProxy, Hosts: []string{"c.example.com"}}, nil},
	} {
		if got := dnsCandidates(c.before, c.after); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

// Every lookup of a save shares one budget, and a lookup that does not finish gives no warning.
func TestDNSMismatchesShareOneBudget(t *testing.T) {
	r := &tlsFakeResolver{block: true}
	hosts := make([]string, 30)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%d.example.com", i)
	}
	start := time.Now()
	got := dnsMismatches(context.Background(), r, hosts, addrs("203.0.113.10"))
	elapsed := time.Since(start)
	if len(got) != 0 {
		t.Errorf("lookups that never answered gave warnings: %+v", got)
	}
	if elapsed < tlsDNSBudget-100*time.Millisecond || elapsed > tlsDNSBudget+time.Second {
		t.Errorf("30 stuck lookups took %v, want about %v in total", elapsed, tlsDNSBudget)
	}
	if n := int(r.calls.Load()); n != tlsDNSParallel {
		t.Errorf("%d lookups started, want %d at a time and none after the budget ran out", n, tlsDNSParallel)
	}
}

func TestStateWarnings(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	inDays := func(d float64) time.Time { return now.Add(time.Duration(d * 24 * float64(time.Hour))) }
	uploaded := func(notAfter time.Time, trusted bool) tlsRead {
		return tlsRead{tls: repository.AppTLS{Source: domain.TLSSourceUploaded}, cert: &repository.AppCertificate{NotAfter: notAfter, Trusted: trusted}}
	}
	acme := func(notAfter *time.Time, source string) tlsRead {
		return tlsRead{tls: repository.AppTLS{Source: domain.TLSSourceACME}, status: &repository.TLSStatus{Source: source, NotAfter: notAfter}}
	}
	at := func(t time.Time) *time.Time { return &t }
	acmeFrom := func(notAfter *time.Time, notBefore time.Time) tlsRead {
		return tlsRead{tls: repository.AppTLS{Source: domain.TLSSourceACME},
			status: &repository.TLSStatus{Source: domain.TLSSourceACME, NotBefore: &notBefore, NotAfter: notAfter}}
	}
	codes := func(r tlsRead) string {
		var out []string
		for _, w := range r.stateWarnings(now) {
			out = append(out, w.Code)
		}
		return strings.Join(out, ",")
	}
	soon, later := inDays(14.5), inDays(15)
	for name, c := range map[string]struct {
		r    tlsRead
		want string
	}{
		"uploaded and fine":              {uploaded(inDays(90), true), ""},
		"uploaded 31 days left":          {uploaded(inDays(31), true), ""},
		"uploaded 30 days left":          {uploaded(inDays(30), true), tlsWarnExpiresSoon},
		"uploaded 29.5 days left":        {uploaded(inDays(29.5), true), tlsWarnExpiresSoon},
		"uploaded not trusted":           {uploaded(inDays(90), false), tlsWarnNotTrusted},
		"uploaded not trusted and soon":  {uploaded(inDays(3), false), tlsWarnNotTrusted + "," + tlsWarnExpiresSoon},
		"uploaded expired":               {uploaded(inDays(-2), true), tlsWarnExpiresSoon},
		"acme 15 days left":              {acme(&later, domain.TLSSourceACME), ""},
		"acme 14.5 days left":            {acme(&soon, domain.TLSSourceACME), tlsWarnExpiresSoon},
		"acme report of the other kind":  {acme(&soon, domain.TLSSourceUploaded), ""},
		"acme without a certificate yet": {acme(nil, domain.TLSSourceACME), ""},
		"no source":                      {tlsRead{tls: repository.AppTLS{}, cert: &repository.AppCertificate{NotAfter: inDays(1)}}, ""},
		"acme source, old upload kept":   {tlsRead{tls: repository.AppTLS{Source: domain.TLSSourceACME}, cert: &repository.AppCertificate{NotAfter: inDays(1)}}, ""},
		"acme of 90 days, 14.5 left":     {acmeFrom(&soon, inDays(14.5-90)), tlsWarnExpiresSoon},
		"acme of 6 days, 3 days left":    {acmeFrom(at(inDays(3)), inDays(3-6)), ""},
		"acme of 6 days, 1 day left":     {acmeFrom(at(inDays(1)), inDays(1-6)), tlsWarnExpiresSoon},
		"acme of 6 days, expired":        {acmeFrom(at(inDays(-1)), inDays(-1-6)), tlsWarnExpiresSoon},
		"acme of 12 hours, 6 hours left": {acmeFrom(at(inDays(0.25)), inDays(0.25-0.5)), tlsWarnExpiresSoon},
		"uploaded of 6 days, 1 day left": {tlsRead{tls: repository.AppTLS{Source: domain.TLSSourceUploaded}, cert: &repository.AppCertificate{Trusted: true, NotBefore: inDays(1 - 6), NotAfter: inDays(1)}}, tlsWarnExpiresSoon},
	} {
		if got := codes(c.r); got != c.want {
			t.Errorf("%s: warnings %q, want %q", name, got, c.want)
		}
	}
	w := uploaded(inDays(10.5), true).stateWarnings(now)
	if len(w) != 1 || w[0].DaysLeft == nil || *w[0].DaysLeft != 10 || w[0].NotAfter == nil || !w[0].NotAfter.Equal(inDays(10.5)) {
		t.Errorf("expires_soon fields = %+v", w)
	}
	if d := domain.DaysLeft(inDays(-0.5), now); d != -1 {
		t.Errorf("half a day past expiry is %d days left, want -1", d)
	}

	// The dashboard and the expiry mails read one table: a certificate has expires_soon exactly when
	// the mails have a level for it, and the days it shows are the days the mail counts.
	for _, lifetime := range []float64{90, 45, 6} {
		for left := -3.0; left <= 40; left += 0.5 {
			notAfter := inDays(left)
			for source, r := range map[string]tlsRead{
				domain.TLSSourceUploaded: {tls: repository.AppTLS{Source: domain.TLSSourceUploaded}, cert: &repository.AppCertificate{Trusted: true, NotBefore: inDays(left - lifetime), NotAfter: notAfter}},
				domain.TLSSourceACME:     acmeFrom(&notAfter, inDays(left-lifetime)),
			} {
				_, due := domain.ExpiryLevel(source, inDays(left-lifetime), notAfter, now)
				w := r.stateWarnings(now)
				if due != (len(w) == 1) {
					t.Fatalf("%s of %v days with %v left: expires_soon %v, level due %v", source, lifetime, left, len(w) == 1, due)
				}
				if due && (w[0].DaysLeft == nil || *w[0].DaysLeft != domain.DaysLeft(notAfter, now)) {
					t.Fatalf("%s with %v left shows %v days", source, left, w[0].DaysLeft)
				}
			}
		}
	}
}

// tlsGet runs one GET against the app and returns the status and the body.
func tlsGet(t *testing.T, app *fiber.App, path string) (int, []byte) {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest("GET", path, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func TestTLSRefusedAnswers(t *testing.T) {
	for name, c := range map[string]struct {
		err    error
		status int
		code   string
		extra  map[string]any
	}{
		"field":            {&domain.TLSFieldError{Field: "hosts", Msg: "is empty"}, 400, "INVALID_TLS_SETTINGS", map[string]any{"field": "hosts"}},
		"wrapped field":    {fmt.Errorf("save: %w", &domain.TLSFieldError{Field: "mode", Msg: "bad"}), 400, "INVALID_TLS_SETTINGS", map[string]any{"field": "mode"}},
		"listen":           {&domain.TLSConflictError{Code: domain.TLSConflictListen, Field: "listen_port", Address: "0.0.0.0:443", OtherAppName: "shop"}, 409, "LISTEN_CONFLICT", map[string]any{"field": "listen_port"}},
		"host":             {&domain.TLSConflictError{Code: domain.TLSConflictHost, Field: "hosts", Address: "0.0.0.0:443", Host: "a.example.com", OtherAppName: "shop"}, 409, "HOST_CONFLICT", map[string]any{"field": "hosts"}},
		"coverage":         {&repository.TLSCoverageError{Host: "b.example.com"}, 409, "CERTIFICATE_DOES_NOT_COVER", map[string]any{"host": "b.example.com"}},
		"acme too soon":    {&repository.ACMETooSoonError{RetryAfter: 90*time.Second + 400*time.Millisecond}, 409, "ACME_REQUEST_TOO_SOON", map[string]any{"retry_after": float64(91)}},
		"unsupported":      {repository.ErrTLSUnsupported, 409, "TLS_UNSUPPORTED", nil},
		"required":         {repository.ErrCertificateRequired, 409, "CERTIFICATE_REQUIRED", nil},
		"not host bound":   {repository.ErrAgentNotHostBound, 409, "AGENT_NOT_HOST_BOUND", nil},
		"in use":           {repository.ErrCertificateInUse, 409, "CERTIFICATE_IN_USE", nil},
		"wrapped sentinel": {fmt.Errorf("move: %w", repository.ErrTLSUnsupported), 409, "TLS_UNSUPPORTED", nil},
	} {
		failure := c.err
		app := fiber.New()
		app.Get("/", func(c *fiber.Ctx) error {
			handled, answered := tlsRefused(c, failure)
			if !handled {
				return c.SendStatus(599)
			}
			return answered
		})
		status, raw := tlsGet(t, app, "/")
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("%s: %s: %v", name, raw, err)
		}
		if status != c.status || body["code"] != c.code {
			t.Errorf("%s: %d %s, want %d %s", name, status, raw, c.status, c.code)
		}
		if msg, _ := body["error"].(string); msg == "" || len(msg) > 512 || strings.Contains(msg, "\u2014") {
			t.Errorf("%s: error text %q", name, msg)
		}
		for k, v := range c.extra {
			if body[k] != v {
				t.Errorf("%s: %s = %v, want %v in %s", name, k, body[k], v, raw)
			}
		}
		for k := range body {
			if k != "error" && k != "code" && c.extra[k] == nil {
				t.Errorf("%s: unexpected key %q in %s", name, k, raw)
			}
		}
	}

	// What is not a TLS refusal is left to the caller.
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		if handled, _ := tlsRefused(c, errors.New("connection reset")); handled {
			return c.SendStatus(500)
		}
		return c.SendStatus(204)
	})
	if status, raw := tlsGet(t, app, "/"); status != 204 {
		t.Errorf("another error was handled: %d %s", status, raw)
	}
}

// A refused upload answers with the code, the field and a fixed text. Its text is the one of the
// check, never a part of the input.
func TestCertRefusalBody(t *testing.T) {
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		return certRefusal(c, domain.CertFieldChain, domain.CertReasonNamesDoNotCover, "the leaf certificate does not cover a.example.com", "a.example.com")
	})
	app.Get("/plain", func(c *fiber.Ctx) error {
		return certRefusal(c, domain.CertFieldBody, domain.CertReasonTooLarge, "too large", "")
	})
	for path, want := range map[string]map[string]any{
		"/":      {"error": "the leaf certificate does not cover a.example.com", "code": "INVALID_CERTIFICATE", "field": "chain_pem", "reason": "names_do_not_cover", "host": "a.example.com"},
		"/plain": {"error": "too large", "code": "INVALID_CERTIFICATE", "field": "body", "reason": "too_large"},
	} {
		var got map[string]any
		status, raw := tlsGet(t, app, path)
		if err := json.Unmarshal(raw, &got); err != nil || status != 400 || fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: %d %s, want 400 %v", path, status, raw, want)
		}
	}
}

func TestReadUploadFields(t *testing.T) {
	read := func(body string) (*uploadFields, error) { return readUploadFields([]byte(body)) }

	u, err := read(`{ "chain_pem" : "line1\nline2", "other": {"a": ["}", "\"{"], "b": 1}, "key_pem": "k\u0041" }`)
	if err != nil || string(u.chain) != "line1\nline2" || string(u.key) != "kA" {
		t.Fatalf("a body with other fields: %+v, %v", u, err)
	}
	for _, body := range []string{`{}`, `{"chain_pem": null}`, `{"other": 1}`} {
		if u, err := read(body); err != nil || len(u.chain) != 0 || len(u.key) != 0 {
			t.Errorf("%s: %+v, %v, want no bytes", body, u, err)
		}
	}
	// Names match without regard to case, also when they are written with escapes.
	u, err = read(`{"CHAIN_PEM": "c", "Key\u005fPem": "k"}`)
	if err != nil || string(u.chain) != "c" || string(u.key) != "k" {
		t.Errorf("upper-case names: %+v, %v", u, err)
	}
	for name, body := range map[string]string{
		"key twice":           `{"key_pem": "a", "key_pem": "b"}`,
		"key in two cases":    `{"KEY_PEM": "a", "chain_pem": "c", "key_pem": "b"}`,
		"chain twice":         `{"chain_pem": "a", "Chain_Pem": "b"}`,
		"an escaped spelling": `{"key_pem": "a", "key\u005fpem": "b"}`,
		"another field twice": `{"x": 1, "x": 2}`,
	} {
		if u, err := read(body); !errors.Is(err, errUploadDuplicateField) || u != nil {
			t.Errorf("%s: %+v, %v, want a duplicate field", name, u, err)
		}
	}
	for name, body := range map[string]string{
		"not JSON":      "not json",
		"cut off":       `{"key_pem": "a`,
		"an array":      `["a"]`,
		"a string":      `"a"`,
		"chain number":  `{"chain_pem": 5}`,
		"key object":    `{"key_pem": {"a": "b"}}`,
		"two documents": `{} {}`,
		"empty":         "",
	} {
		if u, err := read(body); !errors.Is(err, errUploadBody) || u != nil {
			t.Errorf("%s: %+v, %v, want errUploadBody", name, u, err)
		}
	}

	// The fields are copies: clearing the body leaves them, and wipe clears every one, the chain
	// included, since a combined file puts the key there.
	body := []byte(`{"chain_pem": "CERT\nKEYMATERIAL", "key_pem": "KEYMATERIAL"}`)
	u, err = readUploadFields(body)
	if err != nil {
		t.Fatal(err)
	}
	chain, key := u.chain, u.key
	clear(body)
	if string(chain) != "CERT\nKEYMATERIAL" || string(key) != "KEYMATERIAL" {
		t.Fatalf("the fields share the body: %q %q", chain, key)
	}
	u.wipe()
	for name, buf := range map[string][]byte{"chain": chain, "key": key} {
		if len(bytes.Trim(buf, "\x00")) != 0 {
			t.Errorf("%s was not cleared: %q", name, buf)
		}
	}
}
