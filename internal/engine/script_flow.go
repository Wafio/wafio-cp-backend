package engine

import uddininterp "github.com/bonkzero404/uddin-lang/interpreter"

// checkScriptFlow refuses a break or continue that is not inside a loop of its
// own function. The Go interpreter runs such a script (a break in a function
// ends the loop of its caller, one outside every loop is a runtime error), but
// the Rust interpreter of the WAF agent refuses it when the rule compiles, so
// the rule would never run there. The error names the first such statement in
// source order, in the form of a parse error.
func checkScriptFlow(prog *uddininterp.Program) error {
	var w flowWalker
	w.block(prog.Statements, false)
	if !w.found {
		return nil
	}
	return uddininterp.Error{Position: w.pos, Message: w.keyword + " statement not within a loop"}
}

type flowWalker struct {
	found   bool
	pos     uddininterp.Position
	keyword string
}

func (w *flowWalker) note(pos uddininterp.Position, keyword string) {
	if !w.found || pos.Line < w.pos.Line || pos.Line == w.pos.Line && pos.Column < w.pos.Column {
		w.found, w.pos, w.keyword = true, pos, keyword
	}
}

func (w *flowWalker) block(b uddininterp.Block, inLoop bool) {
	for _, s := range b {
		w.stmt(s, inLoop)
	}
}

func (w *flowWalker) stmt(s uddininterp.Statement, inLoop bool) {
	switch s := s.(type) {
	case *uddininterp.Assign:
		w.expr(s.Target, inLoop)
		w.expr(s.Value, inLoop)
	case *uddininterp.OuterAssign:
		w.expr(s.Value, inLoop)
	case *uddininterp.If:
		w.expr(s.Condition, inLoop)
		w.block(s.Body, inLoop)
		w.block(s.Else, inLoop)
	case *uddininterp.While:
		w.expr(s.Condition, inLoop)
		w.block(s.Body, true)
	case *uddininterp.For:
		w.expr(s.Iterable, inLoop)
		w.block(s.Body, true)
	case *uddininterp.TryCatch:
		w.block(s.TryBlock, inLoop)
		w.block(s.CatchBlock, inLoop)
	case *uddininterp.Return:
		w.expr(s.Result, inLoop)
	case *uddininterp.ExpressionStatement:
		w.expr(s.Expression, inLoop)
	case *uddininterp.FunctionDefinition:
		w.block(s.Body, false)
	case *uddininterp.Break:
		if !inLoop {
			w.note(s.Position(), "break")
		}
	case *uddininterp.Continue:
		if !inLoop {
			w.note(s.Position(), "continue")
		}
	}
}

// expr looks for function bodies: a function starts outside every loop.
func (w *flowWalker) expr(e uddininterp.Expression, inLoop bool) {
	switch e := e.(type) {
	case *uddininterp.Binary:
		w.expr(e.Left, inLoop)
		w.expr(e.Right, inLoop)
	case *uddininterp.Unary:
		w.expr(e.Operand, inLoop)
	case *uddininterp.Ternary:
		w.expr(e.Condition, inLoop)
		w.expr(e.TrueExpr, inLoop)
		w.expr(e.FalseExpr, inLoop)
	case *uddininterp.Call:
		w.expr(e.Function, inLoop)
		for _, a := range e.Arguments {
			w.expr(a, inLoop)
		}
	case *uddininterp.List:
		for _, v := range e.Values {
			w.expr(v, inLoop)
		}
	case *uddininterp.Map:
		for _, it := range e.Items {
			w.expr(it.Key, inLoop)
			w.expr(it.Value, inLoop)
		}
	case *uddininterp.Subscript:
		w.expr(e.Container, inLoop)
		w.expr(e.Subscript, inLoop)
	case *uddininterp.FunctionExpression:
		w.block(e.Body, false)
	}
}
