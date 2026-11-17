// Package apicontract checks the control plane's HTTP responses against the
// OpenAPI document in api/openapi.yaml.
//
// It is test support only: import it from _test.go files, never from code
// that ends up in a binary (depguard rule "contract-tests" in .golangci.yml),
// so release binaries do not link kin-openapi.
//
// A response is checked against the operation "METHOD /path/{template}" it
// answers: the status must be documented (exact code, then NXX, then
// default), the Content-Type must be one the response documents, a JSON body
// must match its schema (JSON Schema 2020-12 for an OpenAPI 3.1 document),
// and a text/event-stream body is split into frames whose data: payloads must
// match the schema of their event name in the operation's x-sse-events list.
package apicontract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/getkin/kin-openapi/openapi3"
	"gopkg.in/yaml.v3"
)

// SpecEnv overrides the spec file the package-level helpers load.
const SpecEnv = "WAFIO_OPENAPI_SPEC"

// SSEExtension is the operation-level list of server-sent events:
// [{event, description, schema, example}], schema = the JSON on data: lines.
const SSEExtension = "x-sse-events"

// Spec is a loaded and validated OpenAPI document with an operation index.
type Spec struct {
	Path string
	doc  *openapi3.T
	ops  []*operation          // every operation, sorted by key
	byID map[string]*operation // key "METHOD /template"

	mu        sync.Mutex
	validated map[string]map[int]int // key → status → count
}

type operation struct {
	key    string
	method string
	path   string
	segs   []string
	op     *openapi3.Operation
	// sse maps an event name to its data schema; nil when the operation
	// documents no x-sse-events. A nil schema means "any data".
	sse map[string]*openapi3.Schema
}

var (
	defaultOnce sync.Once
	defaultSpec *Spec
	defaultErr  error
)

// DefaultSpecPath is $WAFIO_OPENAPI_SPEC or api/openapi.yaml of
// this checkout (found from this source file's location).
func DefaultSpecPath() string {
	if p := os.Getenv(SpecEnv); p != "" {
		return p
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("api", "openapi.yaml")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "api", "openapi.yaml")
}

// Default loads DefaultSpecPath once per test binary.
func Default() (*Spec, error) {
	defaultOnce.Do(func() {
		defaultSpec, defaultErr = Load(DefaultSpecPath())
	})
	return defaultSpec, defaultErr
}

// Load reads, validates and indexes an OpenAPI document.
func Load(path string) (*Spec, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read spec: %w", err)
	}
	return LoadData(path, raw)
}

// LoadData is Load over bytes already read (YAML or JSON).
func LoadData(path string, raw []byte) (*Spec, error) {
	var tree any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		return nil, fmt.Errorf("%s: parse: %w", path, err)
	}
	tree = normalize(tree)
	root, ok := tree.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: top level is not a mapping", path)
	}
	sseNames, err := hoistSSESchemas(root)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	data, err := json.Marshal(root)
	if err != nil {
		return nil, fmt.Errorf("%s: to JSON: %w", path, err)
	}
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(data)
	if err != nil {
		return nil, fmt.Errorf("%s: load: %w", path, err)
	}
	registerStringFormats(doc)
	if err := doc.Validate(context.Background()); err != nil {
		return nil, fmt.Errorf("%s: invalid document: %w", path, err)
	}
	s := &Spec{Path: path, doc: doc, byID: map[string]*operation{}, validated: map[string]map[int]int{}}
	if doc.Paths == nil {
		return nil, fmt.Errorf("%s: no paths", path)
	}
	for tmpl, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			o := &operation{
				key:    strings.ToUpper(method) + " " + tmpl,
				method: strings.ToUpper(method),
				path:   tmpl,
				segs:   splitPath(tmpl),
				op:     op,
			}
			if names, ok := sseNames[o.key]; ok {
				o.sse = map[string]*openapi3.Schema{}
				for event, name := range names {
					if name == "" {
						o.sse[event] = nil
						continue
					}
					ref := doc.Components.Schemas[name]
					if ref == nil || ref.Value == nil {
						return nil, fmt.Errorf("%s: %s event %q: schema not resolved", path, o.key, event)
					}
					o.sse[event] = ref.Value
				}
			}
			s.ops = append(s.ops, o)
			s.byID[o.key] = o
		}
	}
	sort.Slice(s.ops, func(i, j int) bool { return s.ops[i].key < s.ops[j].key })
	return s, nil
}

// normalize turns yaml.v3 output into JSON-marshalable values: mapping keys
// become strings (unquoted response codes decode as ints).
func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = normalize(e)
		}
		return x
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[fmt.Sprint(k)] = normalize(e)
		}
		return out
	case []any:
		for i, e := range x {
			x[i] = normalize(e)
		}
		return x
	default:
		return v
	}
}

var httpMethods = map[string]bool{"get": true, "put": true, "post": true, "delete": true, "options": true, "head": true, "patch": true, "trace": true}

// hoistSSESchemas moves every x-sse-events schema into components.schemas
// under a synthetic name, so the loader resolves its $refs and validates it
// with the rest of the document. It returns key → event → schema name ("" =
// an event documented without a schema).
func hoistSSESchemas(root map[string]any) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	paths, _ := root["paths"].(map[string]any)
	n := 0
	var schemas map[string]any
	tmpls := make([]string, 0, len(paths))
	for t := range paths {
		tmpls = append(tmpls, t)
	}
	sort.Strings(tmpls)
	for _, tmpl := range tmpls {
		item, _ := paths[tmpl].(map[string]any)
		for method, rawOp := range item {
			if !httpMethods[method] {
				continue
			}
			op, _ := rawOp.(map[string]any)
			list, present := op[SSEExtension]
			if !present {
				continue
			}
			key := strings.ToUpper(method) + " " + tmpl
			events, ok := list.([]any)
			if !ok {
				return nil, fmt.Errorf("%s: %s is not a list", key, SSEExtension)
			}
			out[key] = map[string]string{}
			for i, e := range events {
				ev, _ := e.(map[string]any)
				name, _ := ev["event"].(string)
				if name == "" {
					return nil, fmt.Errorf("%s: %s[%d] has no event name", key, SSEExtension, i)
				}
				if _, dup := out[key][name]; dup {
					return nil, fmt.Errorf("%s: %s event %q listed twice", key, SSEExtension, name)
				}
				schema, has := ev["schema"]
				if !has {
					out[key][name] = ""
					continue
				}
				if schemas == nil {
					comps, _ := root["components"].(map[string]any)
					if comps == nil {
						comps = map[string]any{}
						root["components"] = comps
					}
					schemas, _ = comps["schemas"].(map[string]any)
					if schemas == nil {
						schemas = map[string]any{}
						comps["schemas"] = schemas
					}
				}
				n++
				synthetic := fmt.Sprintf("ApicontractSSE%d", n)
				schemas[synthetic] = schema
				out[key][name] = synthetic
			}
		}
	}
	return out, nil
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func isParam(seg string) bool {
	return strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}")
}

// Match finds the operation answering method + path (no query). Literal
// segments beat path parameters, compared left to right, the way Fiber picks
// the route registered for the literal path.
func (s *Spec) Match(method, path string) (string, bool) {
	segs := splitPath(path)
	method = strings.ToUpper(method)
	var best *operation
	for _, o := range s.ops {
		if o.method != method || len(o.segs) != len(segs) {
			continue
		}
		ok := true
		for i, seg := range o.segs {
			if isParam(seg) {
				if segs[i] == "" {
					ok = false
					break
				}
				continue
			}
			if seg != segs[i] {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if best == nil || moreSpecific(o, best) {
			best = o
		}
	}
	if best == nil {
		return "", false
	}
	return best.key, true
}

func moreSpecific(a, b *operation) bool {
	for i := range a.segs {
		pa, pb := isParam(a.segs[i]), isParam(b.segs[i])
		if pa != pb {
			return !pa
		}
	}
	return false
}

// Operations lists every operation key, sorted.
func (s *Spec) Operations() []string {
	out := make([]string, 0, len(s.ops))
	for _, o := range s.ops {
		out = append(out, o.key)
	}
	return out
}

// HasOperation reports whether key ("METHOD /template") is documented.
func (s *Spec) HasOperation(key string) bool {
	_, ok := s.byID[key]
	return ok
}

// record marks an operation as validated with a status in this test binary.
func (s *Spec) record(key string, status int) {
	s.mu.Lock()
	if s.validated[key] == nil {
		s.validated[key] = map[int]int{}
	}
	s.validated[key][status]++
	s.mu.Unlock()
}

// Validated returns how often each operation was validated so far.
func (s *Spec) Validated() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.validated))
	for k, statuses := range s.validated {
		for _, n := range statuses {
			out[k] += n
		}
	}
	return out
}

// ValidatedStatuses returns, per operation, the statuses validated so far.
func (s *Spec) ValidatedStatuses() map[string]map[int]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]map[int]int, len(s.validated))
	for k, statuses := range s.validated {
		out[k] = make(map[int]int, len(statuses))
		for st, n := range statuses {
			out[k][st] = n
		}
	}
	return out
}

// Unvalidated lists the documented operations never validated so far, sorted.
func (s *Spec) Unvalidated() []string {
	seen := s.Validated()
	var out []string
	for _, o := range s.ops {
		if seen[o.key] == 0 {
			out = append(out, o.key)
		}
	}
	return out
}

// NoSuccessValidated lists the operations validated so far only with non-2xx
// statuses: their success shape was never checked. Sorted.
func (s *Spec) NoSuccessValidated() []string {
	var out []string
	for _, o := range s.ops {
		statuses := s.ValidatedStatuses()[o.key]
		if len(statuses) == 0 {
			continue
		}
		ok := false
		for st := range statuses {
			if st >= 200 && st < 300 {
				ok = true
				break
			}
		}
		if !ok {
			out = append(out, o.key)
		}
	}
	return out
}

// Summary is a short report of validation coverage for a package run.
func (s *Spec) Summary() string {
	un := s.Unvalidated()
	no2xx := s.NoSuccessValidated()
	var b strings.Builder
	fmt.Fprintf(&b, "apicontract: %d of %d operations validated, %d with a 2xx (%s)\n", len(s.ops)-len(un), len(s.ops), len(s.ops)-len(un)-len(no2xx), s.Path)
	for _, k := range un {
		fmt.Fprintf(&b, "  never validated: %s\n", k)
	}
	for _, k := range no2xx {
		statuses := s.ValidatedStatuses()[k]
		codes := make([]int, 0, len(statuses))
		for st := range statuses {
			codes = append(codes, st)
		}
		sort.Ints(codes)
		fmt.Fprintf(&b, "  no 2xx validated: %s (only %v)\n", k, codes)
	}
	return b.String()
}

// ErrNoOperation is returned for an operation key the spec does not document.
var ErrNoOperation = errors.New("operation not documented")

// ReportEnv makes RunWithReport print which operations a package run never
// validated.
const ReportEnv = "WAFIO_CONTRACT_REPORT"

// RunWithReport is a TestMain body: it runs the tests and, with
// WAFIO_CONTRACT_REPORT set, prints the default spec's coverage summary
// (validated operations, and every operation never validated in this run).
func RunWithReport(run func() int) int {
	code := run()
	if os.Getenv(ReportEnv) != "" {
		if s, err := Default(); err == nil {
			fmt.Fprint(os.Stderr, s.Summary())
		}
	}
	return code
}

// registerStringFormats makes the formats the spec uses but kin-openapi does
// not know assertions instead of annotations (an unknown format passes any
// string). Document-scoped, so no global state changes.
func registerStringFormats(doc *openapi3.T) {
	doc.SetStringFormatValidator("uuid", openapi3.NewRegexpFormatValidator(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`))
	doc.SetStringFormatValidator("email", openapi3.NewCallbackValidator(func(v string) error {
		addr, err := mail.ParseAddress(v)
		if err != nil || addr.Name != "" || addr.Address != v {
			return &openapi3.SchemaError{Value: v, Reason: "not an email address"}
		}
		return nil
	}))
}
