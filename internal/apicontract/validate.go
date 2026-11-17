package apicontract

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// ValidateResponse fails t when a response does not match the default spec's
// documentation of operation ("GET /api/projects/{id}/hosts/fleet").
func ValidateResponse(t testing.TB, operation string, status int, header http.Header, body []byte) {
	t.Helper()
	s, err := Default()
	if err != nil {
		t.Fatalf("apicontract: %v", err)
	}
	if err := s.Check(operation, status, header, body); err != nil {
		t.Errorf("apicontract: %v", err)
	}
}

// Check validates one response against operation and records the operation
// as validated (also when the response does not match: it was exercised).
func (s *Spec) Check(operation string, status int, header http.Header, body []byte) error {
	o := s.byID[normalizeKey(operation)]
	if o == nil {
		return fmt.Errorf("%s: %w", operation, ErrNoOperation)
	}
	s.record(o.key, status)
	if err := s.checkOp(o, status, header, body); err != nil {
		return fmt.Errorf("%s → %d: %w (body: %s)", o.key, status, err, excerpt(body))
	}
	return nil
}

func normalizeKey(op string) string {
	method, path, ok := strings.Cut(strings.TrimSpace(op), " ")
	if !ok {
		return op
	}
	return strings.ToUpper(method) + " " + strings.TrimSpace(path)
}

func (s *Spec) checkOp(o *operation, status int, header http.Header, body []byte) error {
	if o.op.Responses == nil {
		return errors.New("operation documents no responses")
	}
	ref := o.op.Responses.Status(status)
	if ref == nil {
		ref = o.op.Responses.Default()
	}
	if ref == nil || ref.Value == nil {
		return fmt.Errorf("status %d not documented (documented: %s)", status, strings.Join(documentedStatuses(o.op.Responses), ", "))
	}
	resp := ref.Value
	if o.method == http.MethodHead || status == http.StatusNoContent || status == http.StatusNotModified {
		if len(bytes.TrimSpace(body)) != 0 && status == http.StatusNoContent {
			return errors.New("204 with a body")
		}
		return nil
	}
	ctype := header.Get("Content-Type")
	if len(resp.Content) == 0 {
		if len(bytes.TrimSpace(body)) != 0 {
			return fmt.Errorf("response documents no content, got %q body", ctype)
		}
		return nil
	}
	if ctype == "" {
		if len(body) == 0 {
			return errors.New("documented content, got an empty body without Content-Type")
		}
		return errors.New("body without Content-Type")
	}
	mt, _, err := mime.ParseMediaType(ctype)
	if err != nil {
		return fmt.Errorf("bad Content-Type %q: %v", ctype, err)
	}
	media := resp.Content.Get(mt)
	if media == nil {
		return fmt.Errorf("Content-Type %q not documented (documented: %s)", mt, strings.Join(contentTypes(resp.Content), ", "))
	}
	switch {
	case mt == "text/event-stream":
		return s.checkSSE(o, body)
	case mt == "application/json" || strings.HasSuffix(mt, "+json"):
		if media.Schema == nil || media.Schema.Value == nil {
			return nil
		}
		var v any
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return fmt.Errorf("body is not JSON: %v", err)
		}
		return s.visit(media.Schema.Value, numbersToFloat(v))
	case strings.HasPrefix(mt, "text/"):
		if media.Schema == nil || media.Schema.Value == nil {
			return nil
		}
		return s.visit(media.Schema.Value, string(body))
	default:
		return nil // binary media: the documented type is the contract
	}
}

func (s *Spec) visit(schema *openapi3.Schema, v any) error {
	opts := []openapi3.SchemaValidationOption{openapi3.MultiErrors()}
	if s.doc.IsOpenAPI31OrLater() {
		opts = append(opts, openapi3.EnableJSONSchema2020())
	}
	return compactSchemaError(s.doc.ValidateSchemaJSON(schema, v, opts...))
}

// compactSchemaError keeps one line per schema violation (pointer + reason)
// instead of kin-openapi's schema and value dumps.
func compactSchemaError(err error) error {
	if err == nil {
		return nil
	}
	var lines []string
	var walk func(error)
	walk = func(e error) {
		var me openapi3.MultiError
		if errors.As(e, &me) {
			for _, sub := range me {
				walk(sub)
			}
			return
		}
		var se *openapi3.SchemaError
		if errors.As(e, &se) {
			ptr := "/" + strings.Join(se.JSONPointer(), "/")
			reason, _, _ := strings.Cut(se.Reason, " (string doesn't match pattern")
			lines = append(lines, fmt.Sprintf("at %s: %s", ptr, reason))
			return
		}
		lines = append(lines, strings.SplitN(e.Error(), "\n", 2)[0])
	}
	walk(err)
	sort.Strings(lines)
	out := lines[:0]
	for i, l := range lines {
		if i == 0 || l != lines[i-1] {
			out = append(out, l)
		}
	}
	return errors.New(strings.Join(out, "; "))
}

// numbersToFloat turns json.Number into float64 (kin-openapi's visitor reads
// float64); UseNumber only guarded the decode against precision surprises.
func numbersToFloat(v any) any {
	switch x := v.(type) {
	case json.Number:
		if f, err := x.Float64(); err == nil {
			return f
		}
		return x.String()
	case map[string]any:
		for k, e := range x {
			x[k] = numbersToFloat(e)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = numbersToFloat(e)
		}
		return x
	default:
		return v
	}
}

// SSEFrame is one dispatched server-sent event.
type SSEFrame struct {
	Event string // "message" when the frame names none
	Data  string // data: lines joined with "\n"
	ID    string
}

// ParseSSE splits a text/event-stream body into frames (WHATWG rules: blank
// line dispatches, ":" lines are comments, a frame without data is not
// dispatched). An unterminated last frame is dispatched too.
func ParseSSE(body []byte) []SSEFrame {
	var frames []SSEFrame
	var cur SSEFrame
	var data []string
	hasData := false
	flush := func() {
		if hasData {
			cur.Data = strings.Join(data, "\n")
			if cur.Event == "" {
				cur.Event = "message"
			}
			frames = append(frames, cur)
		}
		cur, data, hasData = SSEFrame{}, nil, false
	}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSuffix(sc.Text(), "\r")
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			cur.Event = value
		case "data":
			data = append(data, value)
			hasData = true
		case "id":
			cur.ID = value
		}
	}
	flush()
	return frames
}

func (s *Spec) checkSSE(o *operation, body []byte) error {
	frames := ParseSSE(body)
	if len(frames) == 0 {
		return nil
	}
	if o.sse == nil {
		return fmt.Errorf("text/event-stream without %s; got event %q", SSEExtension, frames[0].Event)
	}
	var errs []string
	for i, f := range frames {
		schema, ok := o.sse[f.Event]
		if !ok {
			errs = append(errs, fmt.Sprintf("frame %d: event %q not in %s (documented: %s)", i, f.Event, SSEExtension, strings.Join(sseNames(o.sse), ", ")))
			continue
		}
		if schema == nil {
			continue
		}
		var v any
		dec := json.NewDecoder(strings.NewReader(f.Data))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			v = f.Data // not JSON: validate the text itself (a string schema)
		} else {
			v = numbersToFloat(v)
		}
		if err := s.visit(schema, v); err != nil {
			errs = append(errs, fmt.Sprintf("frame %d event %q: %v (data: %s)", i, f.Event, err, excerpt([]byte(f.Data))))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func sseNames(m map[string]*openapi3.Schema) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func documentedStatuses(r *openapi3.Responses) []string {
	var out []string
	for k := range r.Map() {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contentTypes(c openapi3.Content) []string {
	out := make([]string, 0, len(c))
	for k := range c {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func excerpt(b []byte) string {
	const max = 300
	if len(b) <= max {
		return strconv.Quote(string(b))
	}
	return strconv.Quote(string(b[:max])) + "…"
}

// ValidateMatched validates a response against the operation the spec
// documents for method + path (no query); a request no operation documents
// fails t.
func ValidateMatched(t testing.TB, method, path string, status int, header http.Header, body []byte) {
	t.Helper()
	s, err := Default()
	if err != nil {
		t.Fatalf("apicontract: %v", err)
	}
	key, ok := s.Match(method, path)
	if !ok {
		t.Errorf("apicontract: no documented operation for %s %s", method, path)
		return
	}
	if err := s.Check(key, status, header, body); err != nil {
		t.Errorf("apicontract: %s %s: %v", method, path, err)
	}
}
