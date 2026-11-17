package engine

import (
	"bytes"
	"mime/multipart"
	"strings"
	"unicode/utf8"
)

// Field names shared by login protection, path field rules and custom rule
// conditions, so one field means the same request parts everywhere:
//
//   - Form, query and multipart names: every spelling FormKeyMatcher knows
//     (case, PHP name mangling, NUL cut, elements of field[…]), plus a dot path
//     through bracket names with any index between the named segments
//     (FormField: "employees.photo" names employees[0][photo] and
//     employees[a][photo]).
//   - JSON: a dot path (RewriteJSONPath). Keys match case-insensitively, a key
//     may hold several segments ({"user.email": …}), and arrays are walked at
//     the root and between segments.

// LenientFormUnescape decodes '+' and valid %XX escapes and keeps anything
// else literally, as PHP's urldecode and Node's querystring do.
func LenientFormUnescape(s string) string {
	if strings.IndexByte(s, '%') < 0 && strings.IndexByte(s, '+') < 0 {
		return s
	}
	return string(appendFormUnescape(make([]byte, 0, len(s)), s))
}

func appendFormUnescape(b []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '+':
			b = append(b, ' ')
		case c == '%' && i+2 < len(s) && isHexDigit(s[i+1]) && isHexDigit(s[i+2]):
			b = append(b, unhex(s[i+1])<<4|unhex(s[i+2]))
			i += 2
		default:
			b = append(b, c)
		}
	}
	return b
}

// FormKeyMatcher matches form field names against a field (login protection's
// identifier, path field rules, custom rule conditions) the ways frameworks
// bind them: case-insensitively (ASP.NET model binding), after
// PHP's name mangling ("user.name" and "user name" arrive as user_name), cut
// at a NUL byte, as an array or map element ("field[]", "field[0]",
// "field[a]", "field[a][b]": PHP, qs, Rack; Laravel's whereIn reads their
// values), and a dotted field in bracket notation ("user.email" as
// user[email], also user[email][]). It reuses its buffers, so matching
// allocates nothing; one matcher serves one goroutine.
type FormKeyMatcher struct {
	field, php, bracket []byte
	minLen, maxLen      int
	key, mangled        []byte
}

func NewFormKeyMatcher(field string) *FormKeyMatcher {
	m := &FormKeyMatcher{field: []byte(field)}
	m.php = appendPHPFormKey(nil, m.field)
	if segs := strings.Split(field, "."); len(segs) > 1 {
		m.bracket = []byte(segs[0] + "[" + strings.Join(segs[1:], "][") + "]")
	}
	// A matching name is at least as long as the field has runes, and at most
	// the longest spelling percent-encoded, plus spaces, an index and a NUL tail.
	m.minLen = utf8.RuneCountInString(field)
	m.maxLen = 3*max(len(m.field), len(m.bracket)) + 256
	return m
}

// Matches reports whether the name k names the field; urlencoded
// says k is still percent-encoded.
func (m *FormKeyMatcher) Matches(k string, urlencoded bool) bool {
	if len(k) < m.minLen || len(k) > m.maxLen {
		return false
	}
	if urlencoded {
		m.key = appendFormUnescape(m.key[:0], k)
	} else {
		m.key = append(m.key[:0], k...)
	}
	key := m.key
	if i := bytes.IndexByte(key, 0); i >= 0 {
		key = key[:i]
	}
	if m.nameMatches(key) {
		return true
	}
	// An element of an array or map named like the field: the base before the
	// first '[' (field[a][b]) or before the last one (user[email][]).
	if len(key) > 1 && key[len(key)-1] == ']' {
		if i := bytes.IndexByte(key, '['); i > 0 && m.nameMatches(key[:i]) {
			return true
		}
		if i := bytes.LastIndexByte(key, '['); i > 0 && m.nameMatches(key[:i]) {
			return true
		}
	}
	return false
}

func (m *FormKeyMatcher) nameMatches(k []byte) bool {
	if bytes.EqualFold(k, m.field) || (m.bracket != nil && bytes.EqualFold(k, m.bracket)) {
		return true
	}
	m.mangled = appendPHPFormKey(m.mangled[:0], k)
	return bytes.EqualFold(m.mangled, m.php)
}

// appendPHPFormKey appends a field name as PHP registers it: leading spaces
// dropped, ' ' and '.' before the first '[' turned into '_'.
func appendPHPFormKey(b, k []byte) []byte {
	k = bytes.TrimLeft(k, " ")
	end := bytes.IndexByte(k, '[')
	if end < 0 {
		end = len(k)
	}
	for i, c := range k {
		if i < end && (c == ' ' || c == '.') {
			c = '_'
		}
		b = append(b, c)
	}
	return b
}

// FormField matches decoded form, query and multipart names against one
// field. Not safe for concurrent use (FormKeyMatcher reuses its buffers).
type FormField struct {
	lenient *FormKeyMatcher
	segs    []string
}

// NewFormField returns a matcher for field (a name or a dot path).
func NewFormField(field string) *FormField {
	return &FormField{lenient: NewFormKeyMatcher(field), segs: FormNameSegments(field)}
}

// Matches reports whether the decoded name names the field; nameSegs is
// FormNameSegments(name).
func (f *FormField) Matches(name string, nameSegs []string) bool {
	if f.lenient.Matches(name, false) {
		return true
	}
	if len(f.segs) < 2 || len(nameSegs) < len(f.segs) || !strings.EqualFold(nameSegs[0], f.segs[0]) {
		return false
	}
	// The rest of the path in order; any other segment is an index.
	next := 1
	for _, s := range nameSegs[1:] {
		if next < len(f.segs) && strings.EqualFold(s, f.segs[next]) {
			next++
		}
	}
	return next == len(f.segs)
}

// FormNameSegments splits a decoded form name at '[', ']' and '.', after a NUL
// cut and leading spaces (PHP): employees[0][photo] → employees, 0, photo. It
// returns nil for a name without '[' or '.'.
func FormNameSegments(name string) []string {
	if i := strings.IndexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimLeft(name, " ")
	if !strings.ContainsAny(name, "[.") {
		return nil
	}
	return strings.FieldsFunc(name, func(r rune) bool { return r == '[' || r == ']' || r == '.' })
}

// MultipartPartNames returns the names a multipart part may be read under: its
// form name, or, when Go finds none (a second name parameter, a disposition
// other than form-data), every name parameter of its Content-Disposition —
// PHP and Commons FileUpload take the last one and ignore the disposition type.
func MultipartPartNames(p *multipart.Part) []string {
	if n := p.FormName(); n != "" {
		return []string{n}
	}
	var names []string
	for _, cd := range p.Header.Values("Content-Disposition") {
		for _, param := range strings.Split(cd, ";") {
			if k, v, ok := strings.Cut(param, "="); ok && strings.EqualFold(strings.TrimSpace(k), "name") {
				names = append(names, strings.Trim(strings.TrimSpace(v), `"`))
			}
		}
	}
	return names
}

// RewriteJSONPath replaces every value the dot path field names in node with
// fn(value). With whole, a named array is one value; otherwise each element
// is (nested arrays too).
func RewriteJSONPath(node any, field string, whole bool, fn func(any) any) {
	switch v := node.(type) {
	case map[string]any:
		for key, child := range v {
			switch {
			case strings.EqualFold(key, field):
				v[key] = rewriteJSONLeaf(child, whole, fn)
			case len(field) > len(key) && field[len(key)] == '.' && strings.EqualFold(field[:len(key)], key):
				RewriteJSONPath(child, field[len(key)+1:], whole, fn)
			}
		}
	case []any:
		for _, elem := range v {
			RewriteJSONPath(elem, field, whole, fn)
		}
	}
}

// WalkJSONPath calls visit with every value the dot path field names in node
// (a named array as one value), like RewriteJSONPath without writing.
func WalkJSONPath(node any, field string, visit func(any)) {
	switch v := node.(type) {
	case map[string]any:
		for key, child := range v {
			switch {
			case strings.EqualFold(key, field):
				visit(child)
			case len(field) > len(key) && field[len(key)] == '.' && strings.EqualFold(field[:len(key)], key):
				WalkJSONPath(child, field[len(key)+1:], visit)
			}
		}
	case []any:
		for _, elem := range v {
			WalkJSONPath(elem, field, visit)
		}
	}
}

func rewriteJSONLeaf(v any, whole bool, fn func(any) any) any {
	list, ok := v.([]any)
	if whole || !ok {
		return fn(v)
	}
	for i := range list {
		list[i] = rewriteJSONLeaf(list[i], whole, fn)
	}
	return list
}
