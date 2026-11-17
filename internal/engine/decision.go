package engine

// Action is the decision output: ALLOW (forward), LOG (forward but log), or BLOCK (reject).
type Action int

const (
	ActionAllow Action = iota
	ActionLog
	ActionBlock
)

// Decision is the outcome of the score stage of the reference pipeline (application.Analyze): the action
// and its score. Only the semantic engines score a request, so the stage starts from an allow with score
// 0; bot score mode raises it.
type Decision struct {
	Action Action
	Score  int
}
