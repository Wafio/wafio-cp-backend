package httpadapter

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// concreteServerFields take *agentserver.Server itself (not an interface), so a
// nil server stays a nil pointer the handler can test.
var concreteServerFields = map[string]bool{
	"Server": true, // BlockWindowHandler.Server *agentserver.Server
}

// Typed-nil guard: in fiber.go, agentServer may reach a handler field only
// inside `if agentServer != nil { … }`. Stored straight into an interface
// field, a nil *agentserver.Server makes a non-nil interface, the handler's nil
// check never fires and the route panics when gRPC is off (GET
// …/agents/:agentId/security-data answered 500).
func TestAgentServerReachesInterfacesOnlyWhenNonNil(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fiber.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	isServer := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == "agentServer"
	}
	guarded := func(stack []ast.Node) bool {
		for _, n := range stack {
			ifs, ok := n.(*ast.IfStmt)
			if !ok {
				continue
			}
			if be, ok := ifs.Cond.(*ast.BinaryExpr); ok && be.Op == token.NEQ && isServer(be.X) {
				if id, ok := be.Y.(*ast.Ident); ok && id.Name == "nil" {
					return true
				}
			}
		}
		return false
	}
	found := 0
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		switch x := n.(type) {
		case *ast.KeyValueExpr:
			if isServer(x.Value) {
				key, _ := x.Key.(*ast.Ident)
				if key == nil || !concreteServerFields[key.Name] {
					t.Errorf("%s: agentServer in a composite literal field; assign it under `if agentServer != nil`", fset.Position(x.Pos()))
				}
			}
		case *ast.AssignStmt:
			for _, rhs := range x.Rhs {
				if !isServer(rhs) {
					continue
				}
				found++
				if !guarded(stack) {
					t.Errorf("%s: agentServer assigned outside `if agentServer != nil`", fset.Position(x.Pos()))
				}
			}
		}
		return true
	})
	if found == 0 {
		t.Fatal("no guarded agentServer assignments found: did the wiring move out of fiber.go?")
	}
}
