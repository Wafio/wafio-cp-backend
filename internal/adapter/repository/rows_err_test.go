package repository

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// rowsErrPending lists scan loops tolerated without a rows.Err() check
// (keys "file.go:Func:var"). It is empty since the sweep finished
// (2026-10-16); do not add entries — check rows.Err().
var rowsErrPending = map[string]bool{}

// TestScanLoopsCheckRowsErr guards this: pgx reports a read error that ends
// iteration only through Rows.Err(). A loop over Query() rows that never
// checks it returns a cut-short list as success (200 with a partial page).
// golangci-lint's rowserrcheck sees only some of these shapes with pgx's
// Rows interface, so this walks the package source itself.
func TestScanLoopsCheckRowsErr(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var missing []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			for _, v := range rowsMissingErr(fn.Body) {
				key := name + ":" + fn.Name.Name + ":" + v
				if !rowsErrPending[key] {
					missing = append(missing, key)
				}
			}
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("%s: scan loop over Query() rows never checks rows.Err()", m)
	}
}

// The guard itself must still flag a loop without rows.Err() and pass one
// with it, now that nothing is tolerated.
func TestRowsMissingErrDetects(t *testing.T) {
	const src = `package p
func bad() { rows, _ := db.Query(ctx, "q"); for rows.Next() {} }
func good() { rows, _ := db.Query(ctx, "q"); for rows.Next() {}; _ = rows.Err() }`
	f, err := parser.ParseFile(token.NewFileSet(), "p.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			got[fn.Name.Name] = rowsMissingErr(fn.Body)
		}
	}
	if len(got["bad"]) != 1 || got["bad"][0] != "rows" {
		t.Fatalf("bad loop not flagged: %v", got["bad"])
	}
	if len(got["good"]) != 0 {
		t.Fatalf("checked loop flagged: %v", got["good"])
	}
}

// rowsMissingErr returns the names of variables assigned from a .Query(...)
// call in body that are iterated with .Next() but never asked for .Err().
func rowsMissingErr(body *ast.BlockStmt) []string {
	queried := map[string]bool{}
	called := map[string]map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Rhs) != 1 || len(x.Lhs) == 0 {
				return true
			}
			call, ok := x.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Query" {
				return true
			}
			if id, ok := x.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
				queried[id.Name] = true
			}
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok {
				if called[id.Name] == nil {
					called[id.Name] = map[string]bool{}
				}
				called[id.Name][x.Sel.Name] = true
			}
		}
		return true
	})
	var out []string
	for v := range queried {
		if called[v]["Next"] && !called[v]["Err"] {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
