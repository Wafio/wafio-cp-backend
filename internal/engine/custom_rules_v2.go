package engine

// Custom Rules v2 shared types. Data contracts only — evaluation and parsing
// live in custom_rules.go / parsed_body.go / transforms.go / tuning.go.

// ParsedBody is the content-type-aware parse of a request body, computed once
// per request and cached on WAFRuleContext. Unknown / unparsed content types
// leave all collections nil; raw bytes remain in WAFRuleContext.Body.
type ParsedBody struct {
	// ContentType is the normalized request Content-Type (charset stripped).
	ContentType string
	// JSON holds the parsed JSON document (any type) when the body is JSON.
	// Flattened accessor names are dotted paths: json.a.0.b
	JSON any
	// JSONFlat maps flattened dotted names -> scalar leaf values.
	JSONFlat map[string]string
	// Form holds urlencoded body fields (application/x-www-form-urlencoded).
	// Duplicate keys are comma-joined.
	Form map[string]string
	// FormPairs is every urlencoded pair in order (ParseFormPairs).
	FormPairs []FormValue
	// Multipart holds multipart/form-data part values by field name.
	Multipart map[string]string
	// MultipartParts is every named part in order, with every name it may be
	// read under (MultipartPartNames).
	MultipartParts []MultipartPart
	// MultipartFilenames maps part field name -> client-provided filename.
	MultipartFilenames map[string]string
	// MultipartContentTypes maps part field name -> part Content-Type.
	MultipartContentTypes map[string]string
	// FilesCount is the number of multipart file parts (has filename).
	FilesCount int
	// ParseError is non-empty when the body declared JSON/urlencoded/multipart
	// but failed to parse.
	ParseError string
}

// FormValue is one name=value pair of a form body or query string.
type FormValue struct{ Name, Value string }

// MultipartPart is one named multipart part: its value (a file part's first
// bytes), filename and Content-Type.
type MultipartPart struct {
	Names                        []string
	Value, Filename, ContentType string
}

// TuningRule is a mode="tuning" rule resolved into a per-request TuningPlan
// before the detection engines run.
type TuningRule struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	Enabled   bool         `json:"enabled"`
	Priority  int          `json:"priority"`
	CreatedAt int64        `json:"created_at,omitempty"` // unix seconds; stable-order tie-break
	Scope     TuningScope  `json:"scope"`
	Target    TuningTarget `json:"target"`
	Engine    string       `json:"engine"` // semantic | both (crs: read from stored rules, no effect)
	Effect    TuningEffect `json:"effect"`
}

type TuningScope struct {
	Logic      string          `json:"logic"` // and | or
	Conditions []RuleCondition `json:"conditions"`
}

type TuningTarget struct {
	Components []string `json:"components"`
	Match      string   `json:"match"` // exact | prefix | regex | any
}

type TuningEffect struct {
	SkipSemantic []string `json:"skip_semantic,omitempty"`
	ScanMode     string   `json:"scan_mode,omitempty"`
	// Action "log" records a blocking detection of a matched request as LOG and lets the request through.
	// It is the only value a save accepts.
	Action string `json:"action,omitempty"`
	// Weaken is the key of a rule written before Action: it is read and never written (NormalizeTuningRules
	// turns it into Action "log" or drops it).
	Weaken *TuningWeaken `json:"weaken,omitempty"`
}

// TuningActionLog is the one value of a tuning effect's action.
const TuningActionLog = "log"

// WeakenMeansLog reports whether a legacy weaken effect read as "log only": it lowered scores (a multiplier
// above 0 and below 1) or raised the block threshold (a positive block delta). Any other weaken did nothing
// a detection can show and is dropped.
func WeakenMeansLog(scoreMultiplier float64, blockDelta int) bool {
	return (scoreMultiplier > 0 && scoreMultiplier < 1) || blockDelta > 0
}

type TuningWeaken struct {
	// SensitivityDelta is accepted and stored for rules written before no
	// engine gated on a sensitivity level; nothing reads it.
	SensitivityDelta int                 `json:"sensitivity_delta,omitempty"`
	ScoreMultiplier  float64             `json:"score_multiplier,omitempty"`
	ThresholdDelta   *TuningThresholdDlt `json:"threshold_delta,omitempty"`
}

type TuningThresholdDlt struct {
	Block int `json:"block,omitempty"`
	Log   int `json:"log,omitempty"`
}

// TuningPlan is the merged result of all matching tuning rules for one
// request. The pipeline consults it at each engine stage.
type TuningPlan struct {
	// MatchedRuleIDs lists tuning rules whose scope matched (for telemetry).
	MatchedRuleIDs []string
	// SkipSemanticEngines lists semantic engine names to skip; "*" = all.
	SkipSemanticEngines map[string]bool
	// SkipSemanticAll disables the whole semantic stage within scope.
	SkipSemanticAll bool
	// ScanMode: "" | default | both | disabled (crs_only and semantic_only
	// read as default, see CanonicalScanMode).
	ScanMode string
	// ScoreMultiplier applied to engine scores within scope (0 = untouched).
	ScoreMultiplier float64
	// BlockDelta / LogDelta raise decision thresholds within scope.
	BlockDelta int
	LogDelta   int
	// Targets restricts effects to specific request components
	// (parameter/header/cookie/JSON key names). Empty = whole request.
	Targets []TuningTarget
}
