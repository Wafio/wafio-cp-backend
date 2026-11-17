package domain

import (
	"bytes"
	"net/url"
	"strconv"
	"strings"
)

// Decision secret redaction.
//
// A WAF decision carries request headers, the query string, the URI and the
// body (body_preview, request_body) to the control plane, where they are
// stored (waf_decisions), streamed (SSE) and shown in the dashboard.
// Credentials in them — API keys, CSRF and session tokens, signed-URL
// signatures, passwords in a query string or a login form — must not leave the
// agent as readable text, but the input that triggered the detection is the
// attack evidence and keeps its value.
//
// Which input is the evidence is a MatchEvidence: the match source plus
// whether an engine named that input exactly (it scanned and flagged that
// value) or the source is a guess (a hit on the whole URI).
// Only an exact source keeps a secret-named value, and not for a credential
// check (MatchEvidence.Credential), whose flagged value can be a real
// credential. A guessed source never keeps one.
//
// The functions below are applied on the WAF agent (every decision, in
// emitWAFTelemetry) and again by the control plane at ingest (decisions from
// older agents). They are idempotent: redacting an already redacted decision
// with the same evidence changes nothing.

// DecisionRedactedMarker replaces a credential value; the name is kept.
const DecisionRedactedMarker = "[redacted]"

// redactedLenPrefix starts the reduced form of a credential flagged by a
// credential check: "[redacted:len=<bytes>]".
const redactedLenPrefix = "[redacted:len="

// fieldMaskedMarker is what a path exception's mask field rule
// (PathFieldRule action "mask") writes into the WAF agent's body preview:
// already no credential, left as it is.
const fieldMaskedMarker = "[MASKED]"

// maxKeptAuthHeaderSegment caps the JWT header segment kept from an
// Authorization value named by the match source.
const maxKeptAuthHeaderSegment = 1024

// secretExactNames are names that are credentials only as a whole name
// (normalised: lower case, '_' '.' ' ' '[' ']' read as '-'): too short or too
// common to be a pattern.
var secretExactNames = map[string]bool{
	"key": true, "x-key": true, // Google APIs ?key=
	"sig": true, "x-sig": true, // Azure SAS signature
	"auth": true, "x-auth": true,
	"pass": true, "x-pass": true,
	"ticket": true, // CAS service ticket
	"code":   true, // OAuth 2.0 authorization code (?code=)
}

// secretWords are credentials as one word of a name (user-pwd, connect.sid,
// card-cvv).
var secretWords = map[string]bool{
	"pwd": true, "pw": true, "sid": true, "otp": true, "totp": true, "pin": true,
	"cvv": true, "cvv2": true, "cvc": true, "ssn": true,
}

// secretSubstrings mark a credential anywhere in the compacted name (lower
// case, separators removed), so camelCase query names match too (accessToken,
// apiKey, clientSecret, X-Amz-Security-Token, X-Goog-Api-Key, PHPSESSID).
var secretSubstrings = [][]byte{
	[]byte("token"), []byte("secret"), []byte("password"), []byte("passwd"), []byte("passphrase"),
	[]byte("apikey"), []byte("accesskey"), []byte("privatekey"), []byte("clientkey"), []byte("licensekey"),
	[]byte("masterkey"), []byte("signingkey"), []byte("encryptionkey"), []byte("subscriptionkey"),
	[]byte("functionskey"), []byte("authkey"), []byte("signature"), []byte("hmac"), []byte("credential"),
	[]byte("session"), []byte("sessid"), []byte("csrf"), []byte("xsrf"), []byte("authorization"),
	[]byte("jwt"), []byte("bearer"), []byte("passcode"), []byte("authcode"),
	[]byte("samlresponse"), []byte("samlrequest"), // SAML messages (?SAMLResponse=)
	[]byte("cardnumber"), []byte("creditcard"), []byte("ccnum"), // payment card data in forms
}

// IsSecretFieldName reports whether a header, query parameter, cookie, form
// field or JSON key name is one whose value is treated as a credential in a
// stored decision. Case-insensitive (ASCII); '-', '_', '.', ' ', '[' and ']'
// are separators. It allocates nothing for names up to 128 bytes (it runs for
// every header of every decision on the WAF agent).
func IsSecretFieldName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	var nb, cb [128]byte
	norm, compact := nb[:0], cb[:0]
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case 'A' <= c && c <= 'Z':
			c += 'a' - 'A'
		case c == '_' || c == '.' || c == ' ' || c == '[' || c == ']':
			c = '-'
		}
		norm = append(norm, c)
		if c != '-' {
			compact = append(compact, c)
		}
	}
	norm = bytes.Trim(norm, "-")
	if secretExactNames[string(norm)] {
		return true
	}
	// Manual split: bytes.SplitSeq's iterator made norm escape to the heap.
	for rest := norm; len(rest) > 0; {
		w := rest
		if i := bytes.IndexByte(rest, '-'); i >= 0 {
			w, rest = rest[:i], rest[i+1:]
		} else {
			rest = nil
		}
		if secretWords[string(w)] {
			return true
		}
	}
	// Substrings indexed by first byte: one pass over the name instead of a
	// search per pattern (this runs for every key of a stored body).
	for i, c := range compact {
		for _, sub := range secretSubstringsByFirst[c] {
			if bytes.HasPrefix(compact[i:], sub) {
				return true
			}
		}
	}
	return false
}

// secretSubstringsByFirst groups secretSubstrings by their first byte.
var secretSubstringsByFirst = func() (idx [256][][]byte) {
	for _, s := range secretSubstrings {
		idx[s[0]] = append(idx[s[0]], s)
	}
	return idx
}()

// MatchEvidence is the request input a decision names as its evidence.
//
// Exact is a typed marker, never inferred from Source: true only when an
// engine named that input itself — a semantic engine flagged that header,
// query parameter or body field value, content scanning matched that upload
// field. A source derived after the fact (guesses via
// GuessQueryMatchSource, header guesses from HeaderInjectionFieldsForLog, a
// hit on the whole URI) and every source from an agent that predates the
// marker are not exact, and keep no secret-named value.
//
// Credential marks a verdict of a check whose flagged value can be a real
// credential (IsCredentialVerdict: the JWT engine on a token, the entropy
// anomaly heuristic on a strong password): an exact source then keeps only a
// reduced form of a secret-named value — a JWT's header segment
// ("eyJhbGciOiJub25lIn0.[redacted]") or its length ("[redacted:len=24]").
//
// Flagged is the decoded value of the part the engine flagged, known only on
// the WAF agent (AnalysisResult.MatchValue; in process, never on the wire):
// an exact source then keeps a secret-named input only when it holds that
// value, so a same-named field elsewhere in the request (a victim's token
// beside the injected one, a duplicate cut off the stored copy) is redacted.
// Without it (control plane, older agents) several same-named values of the
// target, counted with names decoded as the engine decodes them, or a body
// copy that may be cut, keep only payload-like values.
type MatchEvidence struct {
	Source     string
	Exact      bool
	Credential bool
	Flagged    *string
}

// GuessedMatch is the evidence of a guessed (or unknown) match source.
func GuessedMatch(source string) MatchEvidence { return MatchEvidence{Source: source} }

// DecisionMatch is the evidence of a decision: its match source, whether the
// engine named that input exactly, and its categories (IsCredentialVerdict).
func DecisionMatch(source string, exact bool, categories []string) MatchEvidence {
	return MatchEvidence{Source: source, Exact: exact, Credential: IsCredentialVerdict(categories)}
}

// credentialCategories are verdict categories whose flagged value can be a
// genuine credential: the JWT engine judges a token's header, the anomaly
// heuristic flags high-entropy values such as strong passwords.
var credentialCategories = [...]string{"JWT", "Anomaly"}

// IsCredentialVerdict reports whether a decision with these categories comes
// from a credential-type check (credentialCategories).
func IsCredentialVerdict(categories []string) bool {
	for _, c := range categories {
		for _, cc := range credentialCategories {
			if strings.EqualFold(strings.TrimSpace(c), cc) {
				return true
			}
		}
	}
	return false
}

// Evidence kinds a match source names.
const (
	evidenceNone      = ""
	evidenceHeader    = "header"
	evidenceQuery     = "query"
	evidenceQueryName = "query_name" // the parameter NAME was the payload
	evidenceCookie    = "cookie"
	evidenceBody      = "body" // a form/multipart field or a JSON key of the body
)

// evidence is a parsed MatchEvidence.
type evidence struct {
	kind, target string
	// multi: the engine judged several values of the target joined (HPP);
	// each value is kept only when it looks like a payload.
	multi bool
	exact bool
	cred  bool
	// flagged: the engine's value of the target (MatchEvidence.Flagged),
	// valueKnown when set.
	flagged    string
	valueKnown bool
	// cut: the body copy may be a prefix of the request body, so the target
	// may occur again past its end (control plane, flagged value unknown).
	cut bool
}

func (m MatchEvidence) parse() evidence {
	kind, target, multi := parseMatchSourceMulti(m.Source)
	e := evidence{kind: kind, target: target, multi: multi, exact: m.Exact, cred: m.Credential}
	if m.Exact && m.Flagged != nil {
		e.flagged, e.valueKnown = *m.Flagged, true
	}
	return e
}

// countsTargets reports whether the evidence must count the target's values
// to know which one was flagged: an exact, single-valued, secret-named
// target whose flagged value is unknown.
func (e evidence) countsTargets() bool {
	return e.exact && !e.multi && !e.valueKnown && IsSecretFieldName(e.target)
}

// namedValue is what a secret-named value the evidence names is stored as:
// itself for an exact source (only when it is the flagged value, if known),
// its reduced form for a credential check, the marker for a guessed source.
func (e evidence) namedValue(v string) string {
	switch {
	case isRedactedValue(v):
		return v
	case !e.exact:
		return DecisionRedactedMarker
	case e.valueKnown && !e.isFlagged(v):
		return DecisionRedactedMarker
	case e.cred:
		return reduceCredentialValue(v)
	}
	return v
}

// isFlagged reports whether a stored value (raw text of the copy) is the
// flagged value: as is, trimmed, or decoded the way the engine decoded it
// (JSON string escapes; up to two rounds of URL decoding, as the query scan
// decodes the URI and then each value).
func (e evidence) isFlagged(v string) bool {
	if !e.valueKnown {
		return false
	}
	f := e.flagged
	if v == f || strings.TrimSpace(v) == strings.TrimSpace(f) {
		return true
	}
	d := v
	if strings.IndexByte(d, '\\') >= 0 {
		if u, ok := jsonUnescape(d); ok {
			if u == f {
				return true
			}
			d = u
		}
	}
	for range 2 {
		if strings.IndexByte(d, '%') < 0 && strings.IndexByte(d, '+') < 0 {
			break
		}
		u, err := url.QueryUnescape(d)
		if err != nil || u == d {
			break
		}
		if u == f {
			return true
		}
		d = u
	}
	return false
}

// parseMatchSource returns the request input a decision's match_source names.
func parseMatchSource(ms string) (kind, name string) {
	kind, name, _ = parseMatchSourceMulti(ms)
	return kind, name
}

// parseMatchSourceMulti parses a match source. Formats: semantic/bot
// "header:<Name>", semantic "query:<name>", "query:hpp:<name>" (multi),
// "query:name:<name>", body fields "body:<field>", "body:hpp:<field>"
// (multi), "body:<field>:filename|filecontent", JSON body keys
// "body.json:<key>", rule-target style "cookie:<name>", and the matched
// variables an older agent sent: REQUEST_HEADERS:, ARGS_GET:, ARGS:,
// REQUEST_COOKIES:. Everything
// else ("body", "body:name:<field>", "body.json", "path", "path:<pattern>",
// "query", "ws:*", "header:fraction", "") names no header, parameter, cookie
// or field value.
func parseMatchSourceMulti(ms string) (kind, name string, multi bool) {
	ms = strings.TrimSpace(ms)
	i := strings.IndexByte(ms, ':')
	if i <= 0 || i == len(ms)-1 {
		return evidenceNone, "", false
	}
	prefix, rest := strings.ToLower(ms[:i]), ms[i+1:]
	switch prefix {
	case "header", "request_headers":
		return evidenceHeader, rest, false
	case "cookie", "request_cookies":
		return evidenceCookie, rest, false
	case "args_get", "args":
		return evidenceQuery, rest, false
	case "query":
		if n, ok := strings.CutPrefix(rest, "hpp:"); ok && n != "" {
			return evidenceQuery, n, true
		}
		if n, ok := strings.CutPrefix(rest, "name:"); ok && n != "" {
			return evidenceQueryName, n, false
		}
		return evidenceQuery, rest, false
	case "body":
		if n, ok := strings.CutPrefix(rest, "hpp:"); ok && n != "" {
			return evidenceBody, n, true
		}
		if strings.HasPrefix(rest, "name:") {
			return evidenceNone, "", false // the field NAME was the payload
		}
		for _, suf := range [...]string{":filename", ":filecontent"} {
			if n, ok := strings.CutSuffix(rest, suf); ok && n != "" {
				return evidenceBody, n, false
			}
		}
		return evidenceBody, rest, false
	case "body.json":
		return evidenceBody, rest, false
	}
	return evidenceNone, "", false
}

// isRedactedValue reports a value this file wrote: the marker, the reduced
// length form or a JWT header segment followed by the marker.
func isRedactedValue(v string) bool {
	if v == DecisionRedactedMarker || v == fieldMaskedMarker {
		return true
	}
	// Only the exact form the redactor writes, "[redacted:len=<digits>]":
	// a client can send "[redacted:len=1' or '1'='1]" as a value, and
	// counting skips redacted values.
	if digits, ok := strings.CutPrefix(v, redactedLenPrefix); ok {
		if digits, ok = strings.CutSuffix(digits, "]"); ok && digits != "" && strings.Trim(digits, "0123456789") == "" {
			return true
		}
	}
	if seg, ok := strings.CutSuffix(v, "."+DecisionRedactedMarker); ok {
		return isJWTHeaderSegment(seg)
	}
	return false
}

// isJWTHeaderSegment reports a base64url JWT header segment ("eyJ…" is the
// encoding of `{"`), within maxKeptAuthHeaderSegment.
func isJWTHeaderSegment(seg string) bool {
	if len(seg) < 3 || len(seg) > maxKeptAuthHeaderSegment || !strings.HasPrefix(seg, "eyJ") {
		return false
	}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// reduceCredentialValue is the stored form of a secret-named value a
// credential check flagged: a JWT keeps its header segment (alg/kid, what the
// JWT engine judges), anything else only its length. No hash: an unsalted
// digest prefix of a password is a guess verifier.
func reduceCredentialValue(v string) string {
	t := strings.TrimSpace(v)
	if isRedactedValue(t) {
		return t
	}
	if seg, _, ok := strings.Cut(t, "."); ok && isJWTHeaderSegment(seg) {
		return seg + "." + DecisionRedactedMarker
	}
	return redactedLenPrefix + strconv.Itoa(len(v)) + "]"
}

// urlValuedHeaders hold a URL whose query string can carry credentials
// (?token= in a Referer); only their secret-named query values are redacted.
var urlValuedHeaders = [...]string{"Referer", "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-URI", "X-Original-URI"}

func isURLValuedHeader(k string) bool {
	for _, n := range urlValuedHeaders {
		if strings.EqualFold(k, n) {
			return true
		}
	}
	return false
}

// headerIs reports whether header name k (as sent, any case) is name.
func headerIs(k, name string) bool { return strings.EqualFold(strings.TrimSpace(k), name) }

// RedactDecisionHeaders redacts a decision's flattened request headers in
// place and returns the map (nil when nothing is left):
//   - Authorization / Proxy-Authorization: dropped, unless the match source
//     names the header — then reduced to its scheme plus, for a Bearer JWT, the
//     header segment (alg/kid, what the analyzer scans), e.g.
//     "Bearer eyJhbGciOiJub25lIn0.[redacted]".
//   - Set-Cookie: dropped.
//   - Cookie: dropped, unless the match source names one cookie (only that
//     cookie's pairs are kept, its value as for a named secret input below
//     when its name is secret) or the Cookie header (exact: every pair is kept
//     by name, a value only when it looks like an attack payload; guessed:
//     the same, but secret-named cookie values are always redacted).
//   - the header an exact source names keeps its value, with three limits: a
//     URL-valued header (Referer …) still gets its secret-named query and
//     path parameters redacted, except values that look like a payload; a
//     secret-named header holding several comma-separated values keeps only
//     the elements that look like a payload (LooksLikeAttackPayload); a
//     secret-named header flagged by a credential check is reduced
//     (reduceCredentialValue). A guessed source keeps no secret-named value.
//   - any other header with a secret name (IsSecretFieldName) gets
//     DecisionRedactedMarker; URL-valued headers (Referer …) get their
//     secret-named query and path parameter values redacted.
func RedactDecisionHeaders(h map[string]string, m MatchEvidence) map[string]string {
	if len(h) == 0 {
		return nil
	}
	e := m.parse()
	named := func(k string) bool {
		return e.kind == evidenceHeader && strings.EqualFold(strings.TrimSpace(e.target), strings.TrimSpace(k))
	}
	for k, v := range h {
		switch {
		case headerIs(k, "authorization"), headerIs(k, "proxy-authorization"):
			if named(k) {
				h[k] = reduceAuthorization(v)
			} else {
				delete(h, k)
			}
		case headerIs(k, "set-cookie"):
			delete(h, k)
		case headerIs(k, "cookie"):
			var kept string
			switch {
			case e.kind == evidenceCookie:
				kept = namedCookie(v, e)
			case named(k):
				kept = redactCookiePairs(v, e.exact)
			}
			if kept == "" {
				delete(h, k)
			} else {
				h[k] = kept
			}
		case named(k) && isURLValuedHeader(strings.TrimSpace(k)):
			h[k] = redactURI(v, evidence{}, e.exact)
		case named(k) && IsSecretFieldName(k):
			if e.exact && strings.IndexByte(v, ',') >= 0 {
				h[k] = keepPayloadElements(v)
			} else {
				h[k] = e.namedValue(v)
			}
		case named(k):
			// the attack evidence keeps its value
		case IsSecretFieldName(k):
			h[k] = DecisionRedactedMarker
		case isURLValuedHeader(strings.TrimSpace(k)):
			h[k] = redactURI(v, evidence{}, false)
		}
	}
	if len(h) == 0 {
		return nil
	}
	return h
}

// namedCookie keeps the pairs of the cookie e names. A secret-named cookie
// keeps its value as a named input does (evidence.namedValue); several pairs
// of that name keep only payload-like values.
func namedCookie(v string, e evidence) string {
	pairs := cookiePairsNamed(v, e.target)
	if len(pairs) == 0 {
		return ""
	}
	if !IsSecretFieldName(e.target) {
		return strings.Join(pairs, "; ")
	}
	if len(pairs) > 1 || !e.exact {
		// several values: payload-like ones (exact source only)
		return redactCookiePairs(strings.Join(pairs, "; "), e.exact)
	}
	n, val, ok := strings.Cut(pairs[0], "=")
	if !ok {
		return redactCookiePairs(pairs[0], e.exact)
	}
	return n + "=" + e.namedValue(val)
}

// reduceAuthorization keeps an Authorization value's scheme and, for a Bearer
// JWT, its header segment; the rest becomes DecisionRedactedMarker.
func reduceAuthorization(v string) string {
	v = strings.TrimSpace(v)
	scheme, cred, ok := strings.Cut(v, " ")
	if !ok || scheme == "" {
		return DecisionRedactedMarker
	}
	if strings.EqualFold(scheme, "bearer") {
		cred = strings.TrimSpace(cred)
		if seg, _, isJWT := strings.Cut(cred, "."); isJWT && isJWTHeaderSegment(seg) {
			return scheme + " " + seg + "." + DecisionRedactedMarker
		}
	}
	return scheme + " " + DecisionRedactedMarker
}

// keepPayloadElements keeps the comma-separated elements of a secret-named
// header value that look like an attack payload and replaces every other
// element with DecisionRedactedMarker ("<script>, [redacted]"). A value with
// no payload-like element becomes DecisionRedactedMarker.
func keepPayloadElements(v string) string {
	if strings.IndexByte(v, ',') < 0 {
		if LooksLikeAttackPayload(v) {
			return v
		}
		return DecisionRedactedMarker
	}
	parts := strings.Split(v, ",")
	kept := false
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if LooksLikeAttackPayload(p) {
			parts[i] = p
			kept = true
		} else {
			parts[i] = DecisionRedactedMarker
		}
	}
	if !kept {
		return DecisionRedactedMarker
	}
	return strings.Join(parts, ", ")
}

// cookiePairs splits a Cookie value ("a=1; b=2", several headers joined by
// "; " or ", ") into trimmed pairs.
func cookiePairs(v string) []string {
	var out []string
	for p := range strings.SplitSeq(v, ";") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// cookiePairsNamed returns the pairs of the named cookie (nil if none).
func cookiePairsNamed(v, name string) []string {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	var kept []string
	for _, p := range cookiePairs(v) {
		n, _, _ := strings.Cut(p, "=")
		if strings.TrimSpace(n) == name {
			kept = append(kept, p)
		}
	}
	return kept
}

// RedactCookieToSuspicious keeps every cookie by name and its value only when
// the value looks like an injection payload (LooksLikeAttackPayload: a
// token-shaped value — base64, base64url, hex, JWT, quoted or not — never
// does unless it holds "../"); every other value becomes
// DecisionRedactedMarker. A pair without '=' is kept only when suspicious.
// This is the form of a Cookie header an engine named exactly.
func RedactCookieToSuspicious(v string) string { return redactCookiePairs(v, true) }

func redactCookiePairs(v string, secretPayloadKept bool) string {
	pairs := cookiePairs(v)
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		n, val, ok := strings.Cut(p, "=")
		if !ok {
			if LooksLikeAttackPayload(p) {
				out = append(out, p)
			}
			continue
		}
		keep := LooksLikeAttackPayload(val) && (secretPayloadKept || !IsSecretFieldName(n))
		if keep || isRedactedValue(val) {
			out = append(out, p)
		} else {
			out = append(out, n+"="+DecisionRedactedMarker)
		}
	}
	return strings.Join(out, "; ")
}

// LooksLikeAttackPayload reports whether a header, parameter or cookie value
// carries injection syntax. It decides which elements of a multi-valued
// evidence input (comma-separated header values, HPP parameters, the pairs
// of a Cookie header, payload-like values of a Referer) keep their value; it
// never exempts an input by itself otherwise. It reuses the checks of
// HeaderInjectionFieldsForLog (on the raw and the URL-decoded value) plus
// template, expression and traversal syntax (strongAttackMarkers). A
// token-shaped value — only base64/base64url/hex/JWT characters (A-Z a-z 0-9
// + / = _ - . ~ :), optionally in double quotes, also after percent-decoding —
// is never a payload unless it holds "../": the weak markers "--" (a
// base64url run) and '=' beside a quote (padding) are what such tokens
// contain by chance.
func LooksLikeAttackPayload(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || isRedactedValue(v) {
		return false
	}
	if isTokenShaped(v) {
		return strings.Contains(v, "../")
	}
	if strings.IndexByte(v, '%') >= 0 {
		if dec, err := url.PathUnescape(v); err == nil && isTokenShaped(dec) {
			return strings.Contains(dec, "../")
		}
	}
	decoded := v
	if dec, err := url.QueryUnescape(v); err == nil {
		decoded = dec
	}
	return looksSuspiciousHeaderValue(v) || looksSuspiciousHeaderValue(decoded) || hasStrongAttackSyntax(decoded)
}

// strongAttackMarkers are syntax a credential does not contain by chance:
// template/expression ("${", "{{", "$(", backtick, "jndi:"), traversal and
// NUL.
var strongAttackMarkers = [...]string{"${", "{{", "$(", "`", "../", `..\`, "\x00", "jndi:"}

func hasStrongAttackSyntax(v string) bool {
	for _, m := range strongAttackMarkers {
		if strings.Contains(v, m) {
			return true
		}
	}
	return false
}

// isTokenShaped reports whether v (optionally wrapped in one pair of double
// quotes) consists only of base64/base64url/hex/JWT characters (':' for
// signed values such as Express's "s:<id>.<sig>").
func isTokenShaped(v string) bool {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '+' || c == '/' || c == '=' || c == '_' || c == '-' || c == '.' || c == '~' || c == ':':
		default:
			return false
		}
	}
	return true
}

// RedactDecisionQuery replaces the values of secret-named parameters of a raw
// query string (no leading '?'; pairs separated by '&' or ';') with
// DecisionRedactedMarker, keeping names, order and every other byte. The
// parameter an exact source names ("query:<name>", ARGS_GET:<name>) keeps its
// value (reduced for a credential check); one named by "query:hpp:<name>", or
// occurring more than once, keeps only payload-like values; a guessed source
// keeps nothing. For "query:name:<name>" the name is the evidence and is
// never redacted anyway. Names are matched URL-decoded.
func RedactDecisionQuery(q string, m MatchEvidence) string {
	return redactQuery(q, m.parse(), evidenceQuery, false)
}

// redactQuery redacts secret-named values of q ('&' or ';' separated pairs;
// a form body uses pairKind evidenceBody). keepPayload keeps every
// secret-named value that looks like a payload (a URL-valued header named
// exactly as the evidence); otherwise only the parameter e names can be kept.
func redactQuery(q string, e evidence, pairKind string, keepPayload bool) string {
	if q == "" || strings.IndexByte(q, '=') < 0 {
		return q
	}
	if e.kind == pairKind && e.countsTargets() && (e.cut || countPairs(q, e.target) > 1) {
		e.multi = true // which of the values was flagged is unknown
	}
	// The builder starts at the first redacted pair: most queries hold no
	// credential and are returned without allocating.
	var b strings.Builder
	copied := 0 // bytes of q already in b
	changed := false
	for start := 0; start <= len(q); {
		end := strings.IndexAny(q[start:], "&;")
		if end < 0 {
			end = len(q)
		} else {
			end += start
		}
		name, val, ok := strings.Cut(q[start:end], "=")
		if nv, keep := queryValue(name, val, ok, e, pairKind, keepPayload); !keep {
			if !changed {
				b.Grow(len(q) + len(DecisionRedactedMarker))
				changed = true
			}
			b.WriteString(q[copied:start])
			b.WriteString(name)
			b.WriteByte('=')
			b.WriteString(nv)
			copied = end
		}
		start = end + 1
	}
	if !changed {
		return q
	}
	b.WriteString(q[copied:])
	return b.String()
}

// countPairs counts the pairs of q whose URL-decoded name is target and whose
// value is not redacted yet (the WAF agent leaves one: the flagged value).
func countPairs(q, target string) int {
	n := 0
	for pair := range strings.FieldsFuncSeq(q, func(r rune) bool { return r == '&' || r == ';' }) {
		name, val, _ := strings.Cut(pair, "=")
		if isRedactedValue(val) {
			continue
		}
		if dec, err := url.QueryUnescape(name); err == nil {
			name = dec
		}
		if name == target {
			n++
		}
	}
	return n
}

// queryValue decides one pair: keep it as is, or store nv as its value.
func queryValue(name, val string, hasValue bool, e evidence, pairKind string, keepPayload bool) (nv string, keep bool) {
	if !hasValue || val == "" || isRedactedValue(val) {
		return "", true
	}
	dn := name
	if dec, err := url.QueryUnescape(name); err == nil {
		dn = dec
	}
	if !IsSecretFieldName(dn) {
		return "", true
	}
	switch {
	case keepPayload, e.kind == pairKind && dn == e.target && e.exact && e.multi:
		if LooksLikeAttackPayload(val) {
			return "", true
		}
	case e.kind == pairKind && dn == e.target:
		nv = e.namedValue(val)
		return nv, nv == val
	}
	return DecisionRedactedMarker, false
}

// redactPathParams replaces the values of secret-named path parameters
// ("/app;jsessionid=…/x") with DecisionRedactedMarker. A value that looks like
// a payload is kept: no match source names a path parameter, so path
// evidence is kept by content.
func redactPathParams(p string) string {
	if strings.IndexByte(p, ';') < 0 {
		return p
	}
	orig := p
	var b strings.Builder
	changed := false
	for {
		i := strings.IndexByte(p, ';')
		if i < 0 {
			b.WriteString(p)
			break
		}
		b.WriteString(p[:i+1])
		p = p[i+1:]
		end := strings.IndexAny(p, "/;")
		if end < 0 {
			end = len(p)
		}
		seg := p[:end]
		name, val, ok := strings.Cut(seg, "=")
		dn := name
		if dec, err := url.PathUnescape(name); err == nil {
			dn = dec
		}
		if ok && val != "" && !isRedactedValue(val) && IsSecretFieldName(dn) && !LooksLikeAttackPayload(val) {
			changed = true
			b.WriteString(name)
			b.WriteByte('=')
			b.WriteString(DecisionRedactedMarker)
		} else {
			b.WriteString(seg)
		}
		p = p[end:]
	}
	if !changed {
		return orig
	}
	return b.String()
}

// RedactDecisionURI applies RedactDecisionQuery to the query part of a URI or
// URL and redacts secret-named path parameters (";jsessionid=…") of its path.
func RedactDecisionURI(uri string, m MatchEvidence) string {
	return redactURI(uri, m.parse(), false)
}

func redactURI(uri string, e evidence, keepPayload bool) string {
	path, q, hasQuery := strings.Cut(uri, "?")
	np, nq := redactPathParams(path), q
	if hasQuery {
		nq = redactQuery(q, e, evidenceQuery, keepPayload)
	}
	if np == path && nq == q {
		return uri
	}
	if !hasQuery {
		return np
	}
	return np + "?" + nq
}
