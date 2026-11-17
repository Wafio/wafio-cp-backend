package engine

// Content-type-aware request body parsing for Custom Rules v2.
// ParseRequestBody runs once
// per request, inline in the WAF path (<5ms p99 budget): every branch is
// bounded (bytes, parts, part sizes) and single-pass. Raw bytes always remain
// available via WAFRuleContext.Body — parsing is purely additive.

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"sort"
	"strconv"
	"strings"
)

// MaxBodyParseBytes bounds ParseRequestBody input. Larger bodies are left
// unparsed (collections nil, ParseError set) so raw matching still works.
const MaxBodyParseBytes = 64 * 1024

const (
	maxMultipartParts   = 64
	maxPartValueBytes   = 64 * 1024
	maxFilePreviewBytes = 4 * 1024
)

// ParseRequestBody dispatches on the normalized Content-Type:
//
//	application/json (+json suffix, text/json) → JSON tree + JSONFlat map
//	application/x-www-form-urlencoded          → Form map (dup keys comma-joined)
//	multipart/*                                → Multipart maps (bounded)
//	anything else (incl. empty)                → collections nil
//
// Parse failures set ParsedBody.ParseError and leave collections nil.
func ParseRequestBody(contentType string, raw []byte) *ParsedBody {
	full := contentType
	p := &ParsedBody{ContentType: normalizeContentType(contentType)}
	if len(raw) == 0 {
		return p
	}
	if len(raw) > MaxBodyParseBytes {
		p.ParseError = "body exceeds MaxBodyParseBytes"
		return p
	}
	ct := p.ContentType
	switch {
	case ct == "application/json" || ct == "text/json" || strings.HasSuffix(ct, "+json"):
		parseJSONBody(raw, p)
	case ct == "application/x-www-form-urlencoded":
		parseFormBody(raw, p)
	case strings.HasPrefix(ct, "multipart/"):
		parseMultipartBody(full, raw, p)
	}
	return p
}

// normalizeContentType strips parameters (charset, boundary, ...) and lowercases.
func normalizeContentType(ct string) string {
	ct, _, _ = strings.Cut(ct, ";")
	return strings.ToLower(strings.TrimSpace(ct))
}

func parseJSONBody(raw []byte, p *ParsedBody) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // preserve number literals for scalar stringification
	var v any
	if err := dec.Decode(&v); err != nil {
		p.ParseError = "invalid json body"
		return
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		// trailing garbage after the first top-level value (parser differential)
		p.ParseError = "invalid json body"
		return
	}
	p.JSON = v
	p.JSONFlat = make(map[string]string, 8)
	flattenJSON("json", v, p.JSONFlat)
}

// flattenJSON walks the JSON tree building dotted names rooted at
// "json." — objects json.a.b, arrays json.a.0.b. Nulls and empty containers
// produce no entries.
func flattenJSON(prefix string, v any, out map[string]string) {
	switch node := v.(type) {
	case map[string]any:
		for k, child := range node {
			flattenJSON(prefix+"."+k, child, out)
		}
	case []any:
		for i, child := range node {
			flattenJSON(prefix+"."+strconv.Itoa(i), child, out)
		}
	default:
		if s, ok := scalarToString(v); ok {
			out[prefix] = s
		}
	}
}

func parseFormBody(raw []byte, p *ParsedBody) {
	p.FormPairs = ParseFormPairs(string(raw))
	p.Form = make(map[string]string, len(p.FormPairs))
	for _, kv := range p.FormPairs {
		if prev, ok := p.Form[kv.Name]; ok {
			p.Form[kv.Name] = prev + "," + kv.Value // a=1&a=2 → "1,2"
		} else {
			p.Form[kv.Name] = kv.Value
		}
	}
}

// ParseFormPairs splits an urlencoded string into its pairs, decoded like PHP
// and Node (LenientFormUnescape): an invalid escape stays literal and never
// hides the other pairs, as it did with url.ParseQuery.
func ParseFormPairs(s string) []FormValue {
	var out []FormValue
	for pair := range strings.SplitSeq(s, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		out = append(out, FormValue{LenientFormUnescape(k), LenientFormUnescape(v)})
	}
	return out
}

func parseMultipartBody(fullContentType string, raw []byte, p *ParsedBody) {
	_, params, err := mime.ParseMediaType(fullContentType)
	if err != nil || params["boundary"] == "" {
		p.ParseError = "multipart boundary missing"
		return
	}
	reader := multipart.NewReader(bytes.NewReader(raw), params["boundary"])
	p.Multipart = make(map[string]string)
	p.MultipartFilenames = make(map[string]string)
	p.MultipartContentTypes = make(map[string]string)
	for n := 0; n < maxMultipartParts; n++ {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			p.ParseError = "malformed multipart body"
			return
		}
		names := MultipartPartNames(part)
		if len(names) == 0 {
			_ = part.Close() // drains the part; never fails
			continue
		}
		name := names[len(names)-1] // the one PHP reads
		mp := MultipartPart{Names: names, ContentType: part.Header.Get("Content-Type"), Filename: part.FileName()}
		p.MultipartContentTypes[name] = mp.ContentType
		if mp.Filename != "" {
			// File part: keep metadata + a bounded content preview.
			p.FilesCount++
			p.MultipartFilenames[name] = mp.Filename
			preview, _ := io.ReadAll(io.LimitReader(part, maxFilePreviewBytes))
			mp.Value = string(preview)
		} else {
			value, _ := io.ReadAll(io.LimitReader(part, maxPartValueBytes))
			mp.Value = string(value)
		}
		joinMapEntry(p.Multipart, name, mp.Value)
		p.MultipartParts = append(p.MultipartParts, mp)
		_ = part.Close() // drains the part; never fails
	}
}

// joinMapEntry comma-joins duplicate multipart field values (form semantics).
func joinMapEntry(m map[string]string, key, value string) {
	if prev, ok := m[key]; ok && prev != "" {
		m[key] = prev + "," + value
		return
	}
	m[key] = value
}

// ---------------------------------------------------------------------------
// JSON field access (used by getFieldValue)
// ---------------------------------------------------------------------------

// scalarToString stringifies JSON scalars. Numbers keep their literal form
// (json.Number); null is NOT a scalar for join purposes.
func scalarToString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case json.Number:
		return t.String(), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case float32:
		return strconv.FormatFloat(float64(t), 'f', -1, 32), true
	case int:
		return strconv.Itoa(t), true
	case int64:
		return strconv.FormatInt(t, 10), true
	}
	return "", false
}

// resolveJSONPointerAll resolves an RFC 6901 pointer ("" = whole document)
// to every node it names. Two extensions make it read what apps read:
// object keys match case-insensitively (Go structs, ASP.NET), and a "*"
// segment stands for every array element or object value
// (/items/*/sku). Unknown keys, bad indices and scalars with segments left
// name nothing.
func resolveJSONPointerAll(root any, pointer string) []any {
	if pointer == "" {
		return []any{root}
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil
	}
	cur := []any{root}
	for _, raw := range strings.Split(pointer[1:], "/") {
		seg := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		var next []any
		for _, node := range cur {
			switch node := node.(type) {
			case map[string]any:
				keys := make([]string, 0, len(node))
				for k := range node {
					if raw == "*" || strings.EqualFold(k, seg) {
						keys = append(keys, k)
					}
				}
				sort.Strings(keys) // deterministic joins
				for _, k := range keys {
					next = append(next, node[k])
				}
			case []any:
				if raw == "*" {
					next = append(next, node...)
				} else if idx, err := strconv.Atoi(seg); err == nil && idx >= 0 && idx < len(node) {
					next = append(next, node[idx])
				}
			}
		}
		if len(next) == 0 {
			return nil
		}
		cur = next
	}
	return cur
}

// jsonFieldValue resolves a bare "json" (whole flattened document) or
// "json:<pointer>" field value, honoring BodyScope for container nodes:
// key = join of child keys, value = join of child scalar values,
// all/"" = keys then values — all joined with "\n".
func jsonFieldValue(p *ParsedBody, pointer, bodyScope string) string {
	if p == nil {
		return ""
	}
	if pointer == "" {
		return joinMapValues(p.JSONFlat, false)
	}
	nodes := resolveJSONPointerAll(p.JSON, pointer)
	if len(nodes) == 1 {
		s, _ := jsonNodeString(nodes[0], bodyScope)
		return s
	}
	return strings.Join(jsonValueList(nodes, bodyScope), "\n")
}

// jsonValueList is the non-empty string of every resolved node.
func jsonValueList(nodes []any, bodyScope string) []string {
	var out []string
	for _, node := range nodes {
		if s, ok := jsonNodeString(node, bodyScope); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// jsonNodeString is one resolved node as a condition value: a scalar as is, an
// object or array as its keys and/or scalar children (bodyScope).
func jsonNodeString(node any, bodyScope string) (string, bool) {
	var keys, vals []string
	switch node := node.(type) {
	case map[string]any:
		// sorted key order keeps key/value/all joins deterministic
		sorted := make([]string, 0, len(node))
		for k := range node {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		keys = make([]string, 0, len(sorted))
		vals = make([]string, 0, len(sorted))
		for _, k := range sorted {
			keys = append(keys, k)
			if s, isScalar := scalarToString(node[k]); isScalar {
				vals = append(vals, s)
			}
		}
	case []any:
		keys = make([]string, 0, len(node))
		vals = make([]string, 0, len(node))
		for i, v := range node {
			keys = append(keys, strconv.Itoa(i))
			if s, isScalar := scalarToString(v); isScalar {
				vals = append(vals, s)
			}
		}
	default:
		return scalarToString(node)
	}
	switch strings.ToLower(strings.TrimSpace(bodyScope)) {
	case "key":
		return strings.Join(keys, "\n"), true
	case "value":
		return strings.Join(vals, "\n"), true
	default: // "all" / ""
		return strings.Join(append(keys, vals...), "\n"), true
	}
}

// joinMapValues joins map values (keys sorted for determinism). Empty values
// are skipped when skipEmpty is set.
func joinMapValues(m map[string]string, skipEmpty bool) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if skipEmpty && v == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return strings.Join(out, "\n")
}
