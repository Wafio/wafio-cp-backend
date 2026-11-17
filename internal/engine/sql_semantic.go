// Enterprise SQL semantic analysis: multi-signal AST evidence + weighted scoring.
package engine

// ── raw fragment SQLi (TiDB cannot parse these as standalone statements) ──────────
// These cover the most common real-world injection FORMS that arrive as a parameter
// VALUE breaking out of a quoted string in the host query — forms the AST visitor
// misses because the fragment alone is not valid SQL. Each requires a SQL-specific
// discriminator (operator + operand, dedicated function, or keyword pair) so plain
// prose ("meeting at 5 or 6 pm", "sort the list and then filter") never matches.

type SQLSemanticEvidence struct {
	Signal     string  `json:"signal"`
	Confidence float64 `json:"confidence"`
	Weight     float64 `json:"weight"`
	Location   string  `json:"location"`
	Context    string  `json:"context"`
}

type SQLSemanticSeverity string

const (
	SQLSeverityLow      SQLSemanticSeverity = "low"
	SQLSeverityMedium   SQLSemanticSeverity = "medium"
	SQLSeverityHigh     SQLSemanticSeverity = "high"
	SQLSeverityCritical SQLSemanticSeverity = "critical"
)

type SQLSemanticPolicy struct {
	BlockThreshold float64
	SoftThreshold  float64
}

type SQLSemanticInput struct {
	Raw      string
	Location string
}

type SQLSemanticReport struct {
	Raw         string
	Normalized  string
	Evidence    []SQLSemanticEvidence
	Score       float64
	Severity    SQLSemanticSeverity
	Block       bool
	Alert       bool
	Primary     string
	BlockThresh float64
	SoftThresh  float64
}
