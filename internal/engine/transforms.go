package engine

// Named text transformations for custom rule conditions.
// Transforms are applied to the RESOLVED field value (never to the rule value)
// before the operator comparison. Pure stdlib only: this runs inline in the
// WAF path (<5ms p99 budget), so every transform is single-pass and
// allocation-light. Transform names follow the common t:* naming.

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Transform converts an input string into a normalized output string.
type Transform func(string) string

// ValidTransforms is the registry of every usable transform name.
var ValidTransforms = map[string]Transform{
	"lowercase":            strings.ToLower,
	"uppercase":            strings.ToUpper,
	"trim":                 strings.TrimSpace,
	"trim_left":            func(s string) string { return strings.TrimLeftFunc(s, unicode.IsSpace) },
	"trim_right":           func(s string) string { return strings.TrimRightFunc(s, unicode.IsSpace) },
	"url_decode":           urlDecode,
	"url_decode_uni":       urlDecodeUni,
	"html_entity_decode":   htmlEntityDecode,
	"js_decode":            jsDecode,
	"css_decode":           cssDecode,
	"base64_decode":        base64Decode,
	"hex_decode":           hexDecode,
	"sql_hex_decode":       sqlHexDecode,
	"normalize_path":       func(s string) string { return normalizePathT(s, false) },
	"normalize_path_win":   func(s string) string { return normalizePathT(s, true) },
	"compress_whitespace":  compressWhitespace,
	"remove_whitespace":    removeWhitespace,
	"remove_nulls":         removeNulls,
	"replace_nulls":        replaceNulls,
	"remove_comments_char": removeCommentsChar,
	"replace_comments":     replaceComments,
	"cmd_line":             cmdLine,
	"escape_seq_decode":    escapeSeqDecode,
	"md5":                  md5Hex,
	"sha1":                 sha1Hex,
	"sha256":               sha256Hex,
	"length":               func(s string) string { return strconv.Itoa(len(s)) },
}

// ApplyTransforms applies transforms in order. Unknown names abort with an
// error (save-time validation path); use applyTransformsSafe for evaluation.
func ApplyTransforms(input string, names []string) (string, error) {
	for _, name := range names {
		t, ok := ValidTransforms[name]
		if !ok {
			return input, fmt.Errorf("unknown transform %q", name)
		}
		input = t(input)
	}
	return input, nil
}

// applyTransformsSafe applies transforms at evaluation time, silently skipping
// unknown names (a saved rule must never fail closed because of a typo).
func applyTransformsSafe(input string, names []string) string {
	for _, name := range names {
		if t, ok := ValidTransforms[name]; ok {
			input = t(input)
		}
	}
	return input
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func unhexVal(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// isWSByte matches the ASCII whitespace set the whitespace transforms use.
func isWSByte(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	}
	return false
}

func isWordByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_'
}

func isWordRune(r rune) bool {
	return r < 128 && isWordByte(byte(r))
}

// decodeHexRun parses exactly n hex digits at the start of s.
func decodeHexRun(s string, n int) (int64, bool) {
	if len(s) < n {
		return 0, false
	}
	var v int64
	for i := 0; i < n; i++ {
		h, ok := unhexVal(s[i])
		if !ok {
			return 0, false
		}
		v = v<<4 | int64(h)
	}
	return v, true
}

func isValidRuneValue(v int64) bool {
	if v < 0 || v > 0x10FFFF {
		return false
	}
	return v < 0xD800 || v > 0xDFFF // exclude surrogates
}

// ---------------------------------------------------------------------------
// url decoding
// ---------------------------------------------------------------------------

// urlDecode decodes %XX sequences; '+' is left untouched (path semantics).
// Invalid escapes are copied verbatim (best-effort).
func urlDecode(s string) string {
	if !strings.ContainsRune(s, '%') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '%' && i+3 <= len(s) {
			if h1, ok1 := unhexVal(s[i+1]); ok1 {
				if h2, ok2 := unhexVal(s[i+2]); ok2 {
					b.WriteByte(h1<<4 | h2)
					i += 3
					continue
				}
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// urlDecodeUni decodes %uHHHH escapes (IIS-style) and then %XX sequences.
func urlDecodeUni(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '%' && i+6 <= len(s) && (s[i+1] == 'u' || s[i+1] == 'U') {
			if v, ok := decodeHexRun(s[i+2:], 4); ok && isValidRuneValue(v) {
				b.WriteRune(rune(v))
				i += 6
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return urlDecode(b.String())
}

// ---------------------------------------------------------------------------
// entity / escape decoding
// ---------------------------------------------------------------------------

var htmlNamedEntities = map[string]rune{
	"amp": '&', "lt": '<', "gt": '>', "quot": '"', "apos": '\'',
	"nbsp": 0x00A0, "copy": 0x00A9, "reg": 0x00AE, "trade": 0x2122,
	"hellip": 0x2026, "mdash": 0x2014, "ndash": 0x2013,
	"laquo": 0x00AB, "raquo": 0x00BB, "euro": 0x20AC,
	"pound": 0x00A3, "yen": 0x00A5, "cent": 0x00A2,
	"sect": 0x00A7, "para": 0x00B6, "middot": 0x00B7,
	"bull": 0x2022, "dagger": 0x2020, "deg": 0x00B0,
	"plusmn": 0x00B1, "frac12": 0x00BD, "times": 0x00D7, "divide": 0x00F7,
}

// htmlEntityDecode decodes common named entities plus decimal/hex numeric
// references, with or without the trailing semicolon.
func htmlEntityDecode(s string) string {
	if !strings.ContainsRune(s, '&') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '&' {
			b.WriteByte(s[i])
			i++
			continue
		}
		end := -1
		for j := i + 1; j < len(s) && j <= i+10; j++ {
			if s[j] == ';' {
				end = j
				break
			}
			if s[j] == '&' {
				break
			}
		}
		if end == -1 {
			b.WriteByte('&')
			i++
			continue
		}
		name := s[i+1 : end]
		if r, ok := htmlNamedEntities[name]; ok {
			b.WriteRune(r)
			i = end + 1
			continue
		}
		if len(name) > 1 && name[0] == '#' {
			var v int64
			var ok bool
			if name[1] == 'x' || name[1] == 'X' {
				v, ok = decodeHexRun(name[2:], len(name)-2)
			} else {
				var err error
				v, err = strconv.ParseInt(name[1:], 10, 32)
				ok = err == nil && v >= 0
			}
			if ok && isValidRuneValue(v) {
				b.WriteRune(rune(v))
				i = end + 1
				continue
			}
		}
		b.WriteByte('&')
		i++
	}
	return b.String()
}

// jsDecode decodes basic JavaScript escapes: \xHH, \uHHHH and the single-char
// escapes \n \t \r \b \f \v \0 \' \" \\ \/. Unknown escapes drop the backslash.
func jsDecode(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		switch c := s[i+1]; c {
		case 'n':
			b.WriteByte('\n')
			i += 2
		case 't':
			b.WriteByte('\t')
			i += 2
		case 'r':
			b.WriteByte('\r')
			i += 2
		case 'b':
			b.WriteByte('\b')
			i += 2
		case 'f':
			b.WriteByte('\f')
			i += 2
		case 'v':
			b.WriteByte('\v')
			i += 2
		case '0':
			b.WriteByte(0)
			i += 2
		case '\\', '\'', '"', '/':
			b.WriteByte(c)
			i += 2
		case 'x':
			if i+4 <= len(s) {
				if h1, ok1 := unhexVal(s[i+2]); ok1 {
					if h2, ok2 := unhexVal(s[i+3]); ok2 {
						b.WriteByte(h1<<4 | h2)
						i += 4
						continue
					}
				}
			}
			b.WriteByte('\\') // undecodable escape: keep verbatim
			i++
		case 'u':
			if v, ok := decodeHexRun(s[i+2:], 4); ok && isValidRuneValue(v) {
				b.WriteRune(rune(v))
				i += 6
				continue
			}
			b.WriteByte('\\') // undecodable escape: keep verbatim
			i++
		default:
			b.WriteByte(c)
			i += 2
		}
	}
	return b.String()
}

// cssDecode decodes CSS escapes: \HHHHHH (1-6 hex digits, one optional
// following whitespace consumed) and \<char>.
func cssDecode(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := i + 1
		var v int64
		digits := 0
		for j < len(s) && digits < 6 {
			h, ok := unhexVal(s[j])
			if !ok {
				break
			}
			v = v<<4 | int64(h)
			digits++
			j++
		}
		if digits > 0 {
			if j < len(s) && isWSByte(s[j]) {
				j++ // CSS consumes exactly one whitespace after the escape
			}
			if isValidRuneValue(v) {
				b.WriteRune(rune(v))
			}
			i = j
			continue
		}
		if j < len(s) {
			b.WriteByte(s[j])
			i += 2
			continue
		}
		b.WriteByte('\\')
		i++
	}
	return b.String()
}

// base64Decode decodes standard base64 (padded or raw). Invalid input is
// returned unchanged (best-effort, AWS BASE64_DECODE semantics).
func base64Decode(s string) string {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return s
	}
	if out, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		return string(out)
	}
	if out, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil {
		return string(out)
	}
	return s
}

// hexDecode decodes an even-length hex string; anything else is returned
// unchanged.
func hexDecode(s string) string {
	if len(s) == 0 || len(s)%2 != 0 {
		return s
	}
	out := make([]byte, 0, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		h1, ok1 := unhexVal(s[i])
		h2, ok2 := unhexVal(s[i+1])
		if !ok1 || !ok2 {
			return s
		}
		out = append(out, h1<<4|h2)
	}
	return string(out)
}

// sqlHexDecode decodes SQL hex literals ("0x4142" -> "AB"). Input without a
// 0x prefix, or with a non-hex / odd-length payload, is returned unchanged.
func sqlHexDecode(s string) string {
	if len(s) < 4 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X') {
		return s
	}
	payload := s[2:]
	if len(payload)%2 != 0 {
		return s
	}
	out := make([]byte, 0, len(payload)/2)
	for i := 0; i < len(payload); i += 2 {
		h1, ok1 := unhexVal(payload[i])
		h2, ok2 := unhexVal(payload[i+1])
		if !ok1 || !ok2 {
			return s
		}
		out = append(out, h1<<4|h2)
	}
	return string(out)
}

// ---------------------------------------------------------------------------
// path normalization
// ---------------------------------------------------------------------------

// normalizePathT collapses duplicate slashes and resolves "." / ".."
// segments. The win variant first converts backslashes to slashes. Segments
// cannot escape an absolute root; relative paths may keep leading "..".
func normalizePathT(s string, win bool) string {
	src := s
	if win {
		src = strings.ReplaceAll(src, "\\", "/")
	}
	if src == "" || !strings.Contains(src, "/") {
		return src
	}
	abs := strings.HasPrefix(src, "/")
	trailing := len(src) > 1 && strings.HasSuffix(src, "/")
	segs := strings.Split(src, "/")
	out := make([]string, 0, len(segs))
	for _, seg := range segs {
		switch seg {
		case "", ".":
			continue
		case "..":
			if len(out) > 0 && out[len(out)-1] != ".." {
				out = out[:len(out)-1]
			} else if !abs {
				out = append(out, "..")
			}
		default:
			out = append(out, seg)
		}
	}
	res := strings.Join(out, "/")
	if abs {
		res = "/" + res
	}
	if trailing && res != "/" && res != "" {
		res += "/"
	}
	return res
}

// ---------------------------------------------------------------------------
// whitespace / nulls / comments
// ---------------------------------------------------------------------------

func compressWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for i := 0; i < len(s); i++ {
		if isWSByte(s[i]) {
			space = true
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteByte(s[i])
	}
	if space {
		b.WriteByte(' ')
	}
	return b.String()
}

func removeWhitespace(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r < 128 && isWSByte(byte(r)) }) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if !isWSByte(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func removeNulls(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}

func replaceNulls(s string) string {
	return strings.ReplaceAll(s, "\x00", " ")
}

// removeCommentsChar strips the comment MARKERS /* */ -- # (AWS
// REMOVE_COMMENTS_CHAR semantics) — comment content between them is kept.
func removeCommentsChar(s string) string {
	r := strings.NewReplacer("/*", "", "*/", "", "--", "", "#", "")
	return r.Replace(s)
}

// replaceComments replaces whole C-style comments with a single space.
// Unterminated comments are left verbatim (AWS REPLACE_COMMENTS semantics).
func replaceComments(s string) string {
	if !strings.Contains(s, "/*") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for {
		start := strings.Index(s, "/*")
		if start < 0 {
			break
		}
		rel := strings.Index(s[start+2:], "*/")
		if rel < 0 {
			break
		}
		b.WriteString(s[:start])
		b.WriteByte(' ')
		s = s[start+2+rel+2:]
	}
	b.WriteString(s)
	return b.String()
}

// cmdLine is the unix command-line normalization: backslash escapes removed
// (the escaped char is kept), quotes stripped, whitespace compressed.
func cmdLine(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\', c == '"', c == '\'':
			continue
		case isWSByte(c):
			space = true
		default:
			if space {
				b.WriteByte(' ')
				space = false
			}
			b.WriteByte(c)
		}
	}
	if space {
		b.WriteByte(' ')
	}
	return b.String()
}

// escapeSeqDecode decodes C-style escape sequences: \a \b \f \n \r \t \v,
// \\ \' \" \?, \xHH, \uHHHH and 1-3 digit octal. Unknown escapes drop the
// backslash and keep the character.
func escapeSeqDecode(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			i++
			continue
		}
		if i+1 >= len(s) {
			b.WriteByte('\\')
			i++
			continue
		}
		switch c := s[i+1]; c {
		case 'a':
			b.WriteByte('\a')
			i += 2
		case 'b':
			b.WriteByte('\b')
			i += 2
		case 'f':
			b.WriteByte('\f')
			i += 2
		case 'n':
			b.WriteByte('\n')
			i += 2
		case 'r':
			b.WriteByte('\r')
			i += 2
		case 't':
			b.WriteByte('\t')
			i += 2
		case 'v':
			b.WriteByte('\v')
			i += 2
		case '\\', '\'', '"', '?':
			b.WriteByte(c)
			i += 2
		case 'x':
			if i+4 <= len(s) {
				if h1, ok1 := unhexVal(s[i+2]); ok1 {
					if h2, ok2 := unhexVal(s[i+3]); ok2 {
						b.WriteByte(h1<<4 | h2)
						i += 4
						continue
					}
				}
			}
			b.WriteByte('\\') // undecodable escape: keep verbatim
			i++
		case 'u':
			if v, ok := decodeHexRun(s[i+2:], 4); ok && isValidRuneValue(v) {
				b.WriteRune(rune(v))
				i += 6
				continue
			}
			b.WriteByte('\\') // undecodable escape: keep verbatim
			i++
		case '0', '1', '2', '3', '4', '5', '6', '7':
			v := int64(c - '0')
			j := i + 2
			for j < len(s) && j < i+4 && s[j] >= '0' && s[j] <= '7' {
				v = v<<3 | int64(s[j]-'0')
				j++
			}
			b.WriteRune(rune(v))
			i = j
		default:
			b.WriteByte(c)
			i += 2
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// digests
// ---------------------------------------------------------------------------

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha1Hex(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
