package domain

import (
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Body redaction of stored decisions: body_preview (512 B)
// and request_body (≤ 4 KiB) are prefixes of the request body, so a login
// form's password would land in waf_decisions. RedactDecisionBody replaces
// the values of secret-named fields (IsSecretFieldName) of a form-urlencoded
// body, a JSON document (any depth, keys case-insensitive; every value under a
// secret-named key, nested objects and arrays included) and multipart field
// values, keeping every other byte. Both copies are cut prefixes: what parses
// is redacted, a value cut by the prefix is still replaced, and it never
// panics. XML, HTML and bodies that are neither JSON nor carry a '=' are left
// as they are.
//
// The field an exact match source names ("body:<field>", "body.json:<key>")
// keeps its value, as a named query parameter does (evidence.namedValue: a
// credential check keeps only the reduced form; "body:hpp:<field>" or a
// repeated field only payload-like values).

// Body kinds RedactDecisionBody tells apart.
const (
	bodyKindNone = iota
	bodyKindForm
	bodyKindJSON
	bodyKindMultipart
)

// RedactDecisionBody redacts a stored body copy. contentType is either the
// request's Content-Type or the agent's normalised short form ("json",
// "form", "multipart", "xml", "text", …, as in waf_decisions.content_type);
// an unknown or empty type is sniffed. The WAF agent stores a multipart
// body as its "name=value&…" summary, which is redacted as a form.
//
// body is taken as the whole request body; RedactDecisionBodyCopy says
// whether a stored copy may be cut.
func RedactDecisionBody(body, contentType string, m MatchEvidence) string {
	return RedactDecisionBodyCopy(body, contentType, m, true)
}

// Stored body copies of a WAF decision: the agent keeps the first
// DecisionBodyPreviewMax runes as body_preview and the first
// DecisionRequestBodyMax bytes as request_body.
const (
	DecisionBodyPreviewMax = 512
	DecisionRequestBodyMax = 4096
)

// BodyCopyComplete reports whether a stored copy of at most limit bytes (or
// runes) is the whole body of bodySize bytes. A copy cut by runes can grow
// past the cut when invalid UTF-8 is replaced, so its length alone cannot
// say it is whole: only a body no longer than limit, copied byte for byte,
// is.
func BodyCopyComplete(copy string, bodySize, limit int) bool {
	return bodySize > 0 && bodySize <= limit && len(copy) == bodySize && utf8.ValidString(copy)
}

// RedactDecisionBodyCopy is RedactDecisionBody for a stored copy that holds
// the whole request body only when complete is true (len(copy) equals the
// request's body size). An exact source whose flagged value is unknown
// (MatchEvidence.Flagged nil: the control plane) keeps a secret-named target
// of a copy that may be cut only when it looks like a payload: the target
// may occur again past the cut.
func RedactDecisionBodyCopy(body, contentType string, m MatchEvidence, complete bool) string {
	if body == "" {
		return body
	}
	kind, boundary := decisionBodyKind(body, contentType)
	e := m.parse()
	e.cut = !complete
	switch kind {
	case bodyKindForm:
		return redactQuery(body, e, evidenceBody, false)
	case bodyKindJSON:
		return redactJSONBody(body, e)
	case bodyKindMultipart:
		return redactMultipartBody(body, boundary, e)
	}
	return body
}

// decisionBodyKind classifies a stored body copy.
func decisionBodyKind(body, contentType string) (kind int, boundary string) {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	mt, params, _ := strings.Cut(ct, ";")
	mt = strings.TrimSpace(mt)
	switch {
	case mt == "json" || strings.Contains(mt, "json"):
		return bodyKindJSON, ""
	case mt == "form" || mt == "application/x-www-form-urlencoded":
		return bodyKindForm, ""
	case mt == "multipart" || strings.HasPrefix(mt, "multipart/"):
		if strings.HasPrefix(body, "--") {
			return bodyKindMultipart, multipartBoundary(contentType, params, body)
		}
		return bodyKindForm, "" // the agent's summary form
	case mt == "xml" || mt == "html" || mt == "soap" || strings.Contains(mt, "xml") || strings.Contains(mt, "html"):
		return bodyKindNone, ""
	}
	t := strings.TrimLeft(strings.TrimPrefix(body, "\xef\xbb\xbf"), " \t\r\n")
	switch {
	case t == "":
		return bodyKindNone, ""
	case t[0] == '{' || t[0] == '[':
		return bodyKindJSON, ""
	case t[0] == '<':
		return bodyKindNone, ""
	case strings.HasPrefix(t, "--") && strings.Contains(strings.ToLower(t), "content-disposition"):
		return bodyKindMultipart, multipartBoundary("", "", t)
	case strings.IndexByte(t, '=') > 0:
		return bodyKindForm, ""
	}
	return bodyKindNone, ""
}

// multipartBoundary reads the boundary from the Content-Type parameters,
// else from the body's first line ("--<boundary>").
func multipartBoundary(contentType, lowerParams, body string) string {
	if i := strings.Index(lowerParams, "boundary="); i >= 0 {
		// Same offset in the original-case parameters (boundaries are
		// case-sensitive).
		_, origParams, _ := strings.Cut(contentType, ";")
		if len(origParams) == len(lowerParams) {
			b := origParams[i+len("boundary="):]
			if j := strings.IndexByte(b, ';'); j >= 0 {
				b = b[:j]
			}
			if b = strings.Trim(strings.TrimSpace(b), `"`); b != "" {
				return b
			}
		}
	}
	line := body
	if i := strings.IndexAny(body, "\r\n"); i >= 0 {
		line = body[:i]
	}
	return strings.TrimSpace(strings.TrimPrefix(line, "--"))
}

// bodyRewriter copies s into a builder lazily: nothing is allocated until the
// first replacement.
type bodyRewriter struct {
	s       string
	b       strings.Builder
	copied  int
	changed bool
}

func (w *bodyRewriter) replace(start, end int, with string) {
	if start < w.copied || end < start || end > len(w.s) {
		return
	}
	if w.s[start:end] == with {
		return
	}
	if !w.changed {
		w.b.Grow(len(w.s) + 16)
		w.changed = true
	}
	w.b.WriteString(w.s[w.copied:start])
	w.b.WriteString(with)
	w.copied = end
}

func (w *bodyRewriter) result() string {
	if !w.changed {
		return w.s
	}
	w.b.WriteString(w.s[w.copied:])
	return w.b.String()
}

// JSON value modes under a key.
const (
	jsonKeep    = iota // not secret
	jsonRedact         // secret: scalars become "[redacted]"
	jsonNamed          // the key an exact source names: evidence.namedValue
	jsonPerItem        // named but multi-valued: payload-like scalars kept
)

type jsonFrame struct {
	object bool
	mode   int // mode of the values in this container (arrays) / inherited (objects)
}

// maxRedactJSONDepth caps the containers the JSON walk tracks (a fixed
// stack: no allocation per level). Past it the walk no longer knows which
// key a value sits under, so it redacts conservatively: every scalar value
// deeper than the cap becomes DecisionRedactedMarker (a string followed by
// ':' is a key and stays). The semantic engines skip content deeper than
// maxJSONDepth (32), so no exact match source lies there.
const maxRedactJSONDepth = 64

// redactJSONBody replaces the scalar values under secret-named keys of a
// (possibly cut) JSON document. Malformed input is copied through. Keys are
// read as the body scanner reads them (jsonKeyNames: JSON escapes, then
// URL-decoding). When the target's flagged value is unknown (control plane),
// several values of the target key, or a copy that may be cut, keep only
// payload-like values.
func redactJSONBody(s string, e evidence) string {
	if e.kind == evidenceBody && e.countsTargets() {
		if e.cut {
			e.multi = true
		} else if _, n := walkRedactJSON(s, e, true); n > 1 {
			e.multi = true
		}
	}
	out, _ := walkRedactJSON(s, e, false)
	return out
}

// walkRedactJSON walks s byte by byte. With count it rewrites nothing and
// returns the number of keys naming e.target whose value is not redacted yet.
func walkRedactJSON(s string, e evidence, count bool) (string, int) {
	w := bodyRewriter{s: s}
	replace := func(start, end int, with string) {
		if !count {
			w.replace(start, end, with)
		}
	}
	var stack [maxRedactJSONDepth]jsonFrame
	depth, over := 0, 0 // tracked frames, containers past the cap
	// In an object: expectKey until a key string is read, then ':' gives the
	// value mode in pending.
	expectKey := false
	pending := jsonKeep
	countNext := false // the next value is a target key's
	n := 0
	inObject := func() bool { return over == 0 && depth > 0 && stack[depth-1].object }
	valueMode := func() int {
		switch {
		case over > 0:
			return jsonRedact
		case depth == 0:
			return jsonKeep
		case stack[depth-1].object:
			return pending
		}
		return stack[depth-1].mode
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch c {
		case ' ', '\t', '\r', '\n', ':':
			i++
		case ',':
			if inObject() {
				expectKey = true
			}
			i++
		case '{', '[':
			if countNext {
				n++
				countNext = false
			}
			mode := valueMode()
			if mode == jsonNamed {
				// A container under the flagged key: its members keep their
				// own names' rules; under a credential check, or when the
				// flagged value (a string) is known, they are redacted.
				mode = jsonKeep
				if e.cred || e.valueKnown {
					mode = jsonRedact
				}
			}
			if over > 0 || depth == len(stack) {
				over++
			} else {
				stack[depth] = jsonFrame{object: c == '{', mode: mode}
				depth++
			}
			expectKey = c == '{'
			pending = jsonKeep
			i++
		case '}', ']':
			if over > 0 {
				over--
			} else if depth > 0 {
				depth--
			}
			expectKey, countNext = false, false
			i++
		case '"':
			end, closed := jsonStringEnd(s, i)
			inner := s[i+1 : end-boolInt(closed)]
			if over > 0 {
				if !isJSONKeyAt(s, end) && !isRedactedValue(inner) {
					replace(i, end, `"`+DecisionRedactedMarker+`"`)
				}
				i = end
				continue
			}
			if inObject() && expectKey {
				pending = jsonKeyMode(inner, stack[depth-1].mode, e)
				countNext = count && pending >= jsonNamed
				expectKey = false
				i = end
				continue
			}
			if countNext {
				if !isRedactedValue(inner) {
					n++
				}
				countNext = false
			}
			switch valueMode() {
			case jsonRedact:
				if !isRedactedValue(inner) {
					replace(i, end, `"`+DecisionRedactedMarker+`"`)
				}
			case jsonPerItem:
				if !LooksLikeAttackPayload(inner) && !isRedactedValue(inner) {
					replace(i, end, `"`+DecisionRedactedMarker+`"`)
				}
			case jsonNamed:
				if nv := e.namedValue(inner); nv != inner {
					replace(i, end, `"`+nv+`"`)
				}
			}
			i = end
		default:
			// bare literal: number, true/false/null or garbage up to a delimiter
			j := i
			for j < len(s) && !isJSONDelim(s[j]) {
				j++
			}
			if j == i {
				j++
			}
			lit := s[i:j]
			if (inObject() && expectKey) || (over > 0 && isJSONKeyAt(s, j)) {
				i = j // unquoted key: malformed, copied through
				continue
			}
			if countNext {
				n++
				countNext = false
			}
			if lit != "true" && lit != "false" && lit != "null" {
				switch valueMode() {
				case jsonRedact, jsonPerItem:
					replace(i, j, `"`+DecisionRedactedMarker+`"`)
				case jsonNamed:
					if nv := e.namedValue(lit); nv != lit {
						replace(i, j, `"`+nv+`"`)
					}
				}
			}
			i = j
		}
	}
	return w.result(), n
}

// jsonKeyMode is the value mode a key gives its value: named (the target an
// exact source names; per item when it is multi-valued), redact (a secret
// name), else the container's inherited mode.
func jsonKeyMode(rawKey string, inherited int, e evidence) int {
	unescaped, decoded := jsonKeyNames(rawKey)
	secret := IsSecretFieldName(decoded) || (unescaped != decoded && IsSecretFieldName(unescaped))
	switch {
	case !secret:
		return inherited
	case e.kind == evidenceBody && strings.EqualFold(decoded, e.target):
		if e.multi {
			return jsonPerItem
		}
		return jsonNamed
	}
	return jsonRedact
}

// isJSONKeyAt reports whether the next non-space byte at or after i is ':'.
func isJSONKeyAt(s string, i int) bool {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
		i++
	}
	return i < len(s) && s[i] == ':'
}

func isJSONDelim(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', ',', ':', '{', '}', '[', ']', '"':
		return true
	}
	return false
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// jsonStringEnd returns the index just past the string starting at s[i] ('"')
// and whether it was closed (false: cut by the prefix, end = len(s)).
func jsonStringEnd(s string, i int) (end int, closed bool) {
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '"':
			return j + 1, true
		}
	}
	return len(s), false
}

// jsonKeyNames decodes a raw JSON key as the body scanner reads it: JSON
// escapes (jsonUnescape), then URL-decoding when it carries '%'
// (decodeJSONKey). Allocates only for a key with an escape or a '%'.
func jsonKeyNames(raw string) (unescaped, decoded string) {
	unescaped = raw
	if u, ok := jsonUnescape(raw); ok {
		unescaped = u
	}
	return unescaped, decodeJSONKey(unescaped)
}

// jsonUnescape decodes the escapes of a raw JSON string body (no quotes) as
// encoding/json does: a lone or mismatched surrogate becomes U+FFFD. ok is
// false for a malformed escape (raw is returned).
func jsonUnescape(raw string) (string, bool) {
	if strings.IndexByte(raw, '\\') < 0 {
		return raw, true
	}
	b := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c != '\\' {
			b = append(b, c)
			continue
		}
		i++
		if i >= len(raw) {
			return raw, false
		}
		switch raw[i] {
		case '"', '\\', '/':
			b = append(b, raw[i])
		case 'b':
			b = append(b, '\b')
		case 'f':
			b = append(b, '\f')
		case 'n':
			b = append(b, '\n')
		case 'r':
			b = append(b, '\r')
		case 't':
			b = append(b, '\t')
		case 'u':
			r, ok := jsonHex4(raw, i+1)
			if !ok {
				return raw, false
			}
			i += 4
			if utf16.IsSurrogate(r) {
				r2, ok2 := rune(0), false
				if i+2 < len(raw) && raw[i+1] == '\\' && raw[i+2] == 'u' {
					r2, ok2 = jsonHex4(raw, i+3)
				}
				if dec := utf16.DecodeRune(r, r2); ok2 && dec != utf8.RuneError {
					r = dec
					i += 6
				} else {
					r = utf8.RuneError
				}
			}
			b = utf8.AppendRune(b, r)
		default:
			return raw, false
		}
	}
	return string(b), true
}

// jsonHex4 reads the 4 hex digits of a \u escape at raw[i:].
func jsonHex4(raw string, i int) (rune, bool) {
	if i+4 > len(raw) {
		return 0, false
	}
	var r rune
	for k := i; k < i+4; k++ {
		c := raw[k]
		switch {
		case '0' <= c && c <= '9':
			c -= '0'
		case 'a' <= c && c <= 'f':
			c -= 'a' - 10
		case 'A' <= c && c <= 'F':
			c -= 'A' - 10
		default:
			return 0, false
		}
		r = r<<4 | rune(c)
	}
	return r, true
}

// redactMultipartBody replaces the content of secret-named text parts (no
// filename) of a raw multipart body; file parts are left as they are.
func redactMultipartBody(s, boundary string, e evidence) string {
	if boundary == "" {
		return s
	}
	delim := "--" + boundary
	w := bodyRewriter{s: s}
	type part struct {
		name       string
		start, end int // content
	}
	var parts []part
	pos := strings.Index(s, delim)
	for pos >= 0 {
		hdrStart := pos + len(delim)
		if strings.HasPrefix(s[hdrStart:], "--") {
			break // closing delimiter
		}
		next := strings.Index(s[hdrStart:], delim)
		partEnd := len(s)
		if next >= 0 {
			partEnd = hdrStart + next
		}
		seg := s[hdrStart:partEnd]
		hdrEnd, sepLen := strings.Index(seg, "\r\n\r\n"), 4
		if hdrEnd < 0 {
			hdrEnd, sepLen = strings.Index(seg, "\n\n"), 2
		}
		if hdrEnd >= 0 {
			name, isFile := multipartDisposition(seg[:hdrEnd])
			cs, ce := hdrStart+hdrEnd+sepLen, partEnd
			// The line break before the next delimiter belongs to it.
			if next >= 0 {
				if ce-2 >= cs && s[ce-2:ce] == "\r\n" {
					ce -= 2
				} else if ce-1 >= cs && s[ce-1] == '\n' {
					ce--
				}
			}
			if !isFile && name != "" {
				parts = append(parts, part{name: name, start: cs, end: ce})
			}
		}
		if next < 0 {
			break
		}
		pos = partEnd
	}
	if e.kind == evidenceBody && e.countsTargets() {
		n := 0
		for _, p := range parts {
			if p.name == e.target && !isRedactedValue(s[p.start:p.end]) {
				n++
			}
		}
		e.multi = n > 1 || e.cut
	}
	for _, p := range parts {
		if !IsSecretFieldName(p.name) {
			continue
		}
		val := s[p.start:p.end]
		if val == "" || isRedactedValue(val) {
			continue
		}
		nv := DecisionRedactedMarker
		if e.kind == evidenceBody && p.name == e.target {
			if e.exact && e.multi {
				if LooksLikeAttackPayload(val) {
					continue
				}
			} else {
				nv = e.namedValue(val)
			}
		}
		w.replace(p.start, p.end, nv)
	}
	return w.result()
}

// multipartDisposition reads the field name of a part's headers and whether
// it is a file part.
func multipartDisposition(headers string) (name string, isFile bool) {
	for line := range strings.SplitSeq(headers, "\n") {
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "content-disposition") {
			continue
		}
		for p := range strings.SplitSeq(v, ";") {
			pk, pv, ok := strings.Cut(strings.TrimSpace(p), "=")
			if !ok {
				continue
			}
			pv = strings.Trim(strings.TrimSpace(pv), `"`)
			switch strings.ToLower(strings.TrimSpace(pk)) {
			case "name":
				name = pv
			case "filename", "filename*":
				isFile = true
			}
		}
	}
	return name, isFile
}
