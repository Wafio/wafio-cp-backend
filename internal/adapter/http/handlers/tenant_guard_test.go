package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The original cross-tenant leak was five endpoints that took an id out of the request and used it
// without checking whose it was. The fix was five edits. Nothing stopped a
// sixth from being written, and one was: resolveAgentID in host_policy.go
// returned ?agent_id= untouched, and nineteen handlers went through it.
//
// A rule with no machine behind it is a suggestion, so this is the machine.
// These tests read the handler source and fail on the shapes that produce the
// bug, rather than trying to catch each instance after the fact.

// unscopedRepoCalls are repository methods that take a tenant-owned id and no
// project. They are legitimate for callers that have already established the
// tenant, and never legitimate in a handler, where the id came from the
// request.
var unscopedRepoCalls = []string{
	"ListNonWAFAgentsByHost",
}

func TestHandlersDoNotCallUnscopedRepositoryLookups(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var findings []string

	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			for _, banned := range unscopedRepoCalls {
				if sel.Sel.Name == banned {
					pos := fset.Position(call.Pos())
					findings = append(findings, pos.String()+": "+banned)
				}
			}
			return true
		})
	}

	if len(findings) > 0 {
		t.Errorf("handlers must not call repository lookups that take a tenant-owned id "+
			"without a project; the id comes from the request. Use the InProject variant.\n  %s",
			strings.Join(findings, "\n  "))
	}
}

// requestIDSources are the ways a handler reads an identifier the caller chose.
var requestIDSources = []string{"Query", "Params", "FormValue"}

// tenantIDNames are the parameters whose value decides which tenant's data is
// touched. Reading one of these without a project check nearby is the cross-tenant
// leak shape.
var tenantIDNames = map[string]bool{
	"agent_id": true, "host_id": true, "app_id": true,
	"appId": true, "agentId": true, "hostId": true,
}

// The check is deliberately shallow. It asks whether the enclosing function
// refers to the project at all -- not whether it does so correctly, which would
// need dataflow analysis. That is enough: in every instance found so far, the
// bug was the total absence of the project, not a subtle misuse of it.
// resolveAgentID never mentioned it; the handlers that looked suspicious and
// were not, like AppDecisions, pass c.Params("id") straight into the query.
//
// Shallow and running beats thorough and absent.
func TestHandlersReadingTenantIDsMentionTheProject(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var findings []string
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		got, err := findUnscopedTenantReads(path, src)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		findings = append(findings, got...)
	}

	if len(findings) > 0 {
		t.Errorf("a handler that reads a tenant-owned id from the request must scope it "+
			"to the project on the route, or the caller chooses whose data is returned:\n  %s",
			strings.Join(findings, "\n  "))
	}
}

// findUnscopedTenantReads is shared with the self-test below, so the guard is
// exercised against a known-bad function rather than only against a tree that
// currently passes. A detector nobody has seen fail is not evidence.
func findUnscopedTenantReads(path string, src []byte) ([]string, error) {
	fset := token.NewFileSet()
	var findings []string
	{
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return nil, err
		}

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			var readsTenantID string
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				isSource := false
				for _, s := range requestIDSources {
					if sel.Sel.Name == s {
						isSource = true
					}
				}
				if !isSource {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				name := strings.Trim(lit.Value, `"`)
				if tenantIDNames[name] {
					readsTenantID = name
				}
				return true
			})
			if readsTenantID == "" {
				continue
			}

			// token.Pos is an offset across the whole FileSet, not into this
			// file, so it has to go through Position to be used as an index.
			start := fset.Position(fn.Body.Pos()).Offset
			end := fset.Position(fn.Body.End()).Offset
			if start < 0 || end > len(src) || start >= end {
				continue
			}
			body := string(src[start:end])
			// `c.Params("id")` is the project on every /api/projects/:id route,
			// and several handlers pass it straight into the repository call
			// without binding it to a variable; others resolve it through
			// ensureProject and pass proj.ID. Both count. Each of these was
			// checked by hand against the SQL it reaches before being accepted
			// here -- DecisionsGeoAggregatesForApp, for instance, joins agents
			// and filters a.project_id.
			if strings.Contains(body, "projectID") || strings.Contains(body, "ProjectID") ||
				strings.Contains(body, "project_id") || strings.Contains(body, "InProject") ||
				strings.Contains(body, `Params("id")`) ||
				strings.Contains(body, "proj.ID") || strings.Contains(body, "ensureProject") {
				continue
			}
			if tenantGuardExempt[fn.Name.Name] {
				continue
			}
			findings = append(findings, fset.Position(fn.Pos()).String()+": "+
				fn.Name.Name+" reads "+readsTenantID+" and never mentions the project")
		}
	}
	return findings, nil
}

// tenantGuardExempt lists functions that read one of those parameters for a
// reason other than selecting tenant data. Each entry needs a comment saying
// why; an exemption with no reason is how a guard stops guarding.
var tenantGuardExempt = map[string]bool{}

// The guard must fail on the code that actually shipped. This is resolveAgentID
// as it was before the fix: ?agent_id= returned straight to nineteen callers,
// and ?host_id= resolved through an unscoped lookup. If this stops being
// detected, the guard above has quietly become decoration.
func TestGuardDetectsTheBugItWasWrittenFor(t *testing.T) {
	const shipped = `package handlers

func (h *HostPolicyHandler) resolveAgentID(c *fiber.Ctx) (string, error) {
	agentID := c.Query("agent_id")
	if agentID != "" {
		return agentID, nil
	}
	if hostID := c.Query("host_id"); hostID != "" {
		agents, err := h.Repo.EBPF.ListNonWAFAgentsByHost(c.Context(), hostID)
		if err == nil && len(agents) > 0 {
			return agents[0].ID, nil
		}
	}
	return "", nil
}
`
	found, err := findUnscopedTenantReads("shipped.go", []byte(shipped))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("the guard did not flag the exact function that caused the leak; " +
			"it is not detecting anything")
	}
}

// And it must not fire on the fixed form, or it will be silenced by whoever
// meets it next.
func TestGuardAcceptsTheFixedForm(t *testing.T) {
	const fixed = `package handlers

func (h *HostPolicyHandler) resolveAgentID(c *fiber.Ctx) (string, error) {
	projectID, err := h.resolveProjectID(c)
	if err != nil {
		return "", err
	}
	if agentID := c.Query("agent_id"); agentID != "" {
		agent, err := h.Repo.EBPF.GetAgentByID(c.Context(), agentID)
		if err != nil || agent == nil || agent.ProjectID != projectID {
			return "", fiber.NewError(404, "agent not found")
		}
		return agentID, nil
	}
	return "", nil
}
`
	found, err := findUnscopedTenantReads("fixed.go", []byte(fixed))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(found) != 0 {
		t.Fatalf("the guard flags correctly scoped code, which makes it noise: %v", found)
	}
}
