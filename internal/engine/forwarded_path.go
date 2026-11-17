package engine

import (
	"strings"
	"sync"

	"github.com/valyala/fasthttp"
)

// ForwardedPath returns the request path the WAF agent's reverse proxy
// forwards upstream for rawURI (a request-target as received: origin-form
// "/a/b?q", or absolute-form "http://host/a/b?q"), and whether that path is
// free of invalid percent escapes.
//
// On the inline proxy it is the one path every path matcher uses (path
// exceptions in both readings, field rules, custom rules, tuning scope, login
// protection).
// The proxy never re-derives it: it passes fasthttp's ctx.URI().Path().
// Callers without a proxy (raw-URI callers of MatchPathException) do not know
// how their host routes the raw target, so they match on RequestPathFor(rawURI)
// — this path plus the decoded-but-unresolved one — instead.
//
// The result is fasthttp's own normalization — the same code the proxy runs,
// not a re-implementation — so it cannot drift on a fasthttp upgrade:
//   - percent escapes are decoded leniently: an invalid escape ("%zz", a
//     trailing "%" or "%4") stays literal, which is why ok is false for it;
//     "%2f" becomes a real "/" and "%2e%2e" a real "..";
//   - duplicate slashes are collapsed;
//   - "/./" segments are removed and "/x/../" segments resolved (a trailing
//     "/.." too), never above the root; a trailing "/." is kept;
//   - "..;" and other path parameters are left alone (the matchers read them
//     under both the servlet and the literal reading, see
//     cleanPathInterpretations);
//   - the query string and fragment are not part of the path.
//
// The returned path is decoded: the proxy re-quotes it on the wire and the
// upstream decodes it back to exactly this string. It always starts with "/".
// A missing Host header is not modelled (the parse assumes one is present,
// as HTTP/1.1 requires), so "//host/x" is a path, not an authority.
func ForwardedPath(rawURI string) (path string, ok bool) {
	path, _, ok = parseRequestPaths(rawURI)
	return path, ok
}

// RequestPath is what the path matchers of one request read.
//
// Forwarded is always set: the normalized path (ForwardedPath). On the inline
// proxy it is exactly what the upstream receives and is the only reading.
//
// Unresolved is set only for entry points without a proxy, and only when it
// differs from Forwarded: the raw path percent-decoded leniently with dot
// segments, duplicate slashes and path parameters left as sent. A host that
// routes the raw target itself (an SDK app, nginx proxy_pass without a URI
// part) may see either, so matchers treat the two as alternatives:
//   - a matcher that exempts or weakens (custom allow/log rule, tuning scope,
//     engine-disable or override path exception, custom script allow/log)
//     applies only when it matches BOTH readings;
//   - a matcher that blocks or limits (custom block/challenge rule, path
//     block, ip_rules, rate limit, login protection, body size) applies when
//     EITHER reading matches.
//
// NoExemption is set when a non-proxy entry sees an invalid percent escape:
// the host's reading is unknowable, so no exempting matcher applies at all.
type RequestPath struct {
	Forwarded   string
	Unresolved  string
	NoExemption bool
}

// RequestPathFor is the RequestPath of a request known only by its raw
// request-target (no proxy between the WAF and the host): see RequestPath.
func RequestPathFor(rawURI string) RequestPath {
	fwd, unresolved, ok := parseRequestPaths(rawURI)
	rp := RequestPath{Forwarded: fwd, NoExemption: !ok}
	if unresolved != fwd {
		rp.Unresolved = unresolved
	}
	return rp
}

// parseRequestPaths parses rawURI once, the way the proxy's server does, and
// returns the forwarded path, the decoded-but-unresolved path and whether the
// raw path is free of invalid percent escapes.
func parseRequestPaths(rawURI string) (forwarded, unresolved string, ok bool) {
	u := uriPool.Get().(*fasthttp.URI)
	defer func() {
		u.Reset()
		uriPool.Put(u)
	}()
	// Parse errors (a CTL byte, a bad absolute-form host) leave the path at
	// "/", which is also what the proxy would forward for such a request.
	_ = u.Parse(forwardedPathHost, []byte(rawURI))
	orig := u.PathOriginal()
	return string(u.Path()), lenientPathDecode(orig), !HasInvalidPercentEscape(orig)
}

// lenientPathDecode percent-decodes a raw path the way fasthttp does (a '%'
// without two hex digits stays literal; '+' is not a space) and nothing else:
// no slash collapsing, no dot-segment resolution. The result always starts
// with "/".
func lenientPathDecode(raw []byte) string {
	var b strings.Builder
	b.Grow(len(raw) + 1)
	if len(raw) == 0 || raw[0] != '/' {
		b.WriteByte('/')
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '%' && i+2 < len(raw) && isHexDigit(raw[i+1]) && isHexDigit(raw[i+2]) {
			b.WriteByte(unhex(raw[i+1])<<4 | unhex(raw[i+2]))
			i += 2
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// forwardedPathHost stands in for the request's Host header in ForwardedPath:
// fasthttp only splits an authority off the request-target when the target
// contains "://" once a Host header is present, exactly as the proxy's server
// parses it.
var forwardedPathHost = []byte("wafio.invalid")

var uriPool = sync.Pool{New: func() any { return new(fasthttp.URI) }}

// HasInvalidPercentEscape reports whether p (a raw, still-encoded request
// path) contains a '%' that is not followed by two hex digits. fasthttp keeps
// such a '%' literal while it decodes and resolves the rest of the path, so
// the raw spelling and the forwarded path can name different resources; the proxy rejects
// these paths with 400 unless
// proxy.reject_invalid_path_encoding is false.
func HasInvalidPercentEscape[T ~string | ~[]byte](p T) bool {
	for i := 0; i < len(p); i++ {
		if p[i] != '%' {
			continue
		}
		if i+2 >= len(p) || !isHexDigit(p[i+1]) || !isHexDigit(p[i+2]) {
			return true
		}
		i += 2
	}
	return false
}
