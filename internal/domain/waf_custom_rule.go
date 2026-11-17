package domain

import "time"

// CustomRule is an app-scoped WAF custom rule (GUI, script, or tuning mode).
type CustomRule struct {
	ID             string                `json:"id"`
	AppID          string                `json:"app_id"`
	Name           string                `json:"name"`
	Description    string                `json:"description"`
	Enabled        bool                  `json:"enabled"`
	Priority       int                   `json:"priority"`
	Mode           string                `json:"mode"`
	Conditions     []CustomRuleCondition `json:"conditions"`
	ConditionLogic string                `json:"condition_logic"`
	Action         string                `json:"action"`
	Script         string                `json:"script"`
	Tuning         *CustomRuleTuning     `json:"tuning,omitempty"`
	CreatedAt      time.Time             `json:"created_at"`
	UpdatedAt      time.Time             `json:"updated_at"`
	// RegexError is computed per response, not stored: why a regex of the
	// rule (condition or tuning target) is invalid or over the program
	// budget, "" when all are usable. Agents drop such a rule at load, so the dashboard can
	// badge it.
	RegexError string `json:"regex_error"`
}

// CustomRuleCondition is a single predicate in a GUI rule.
// V2 optional knobs (negate, case_sensitive, transforms, body_scope) are
// backward compatible: old {field,operator,value} triples stay valid.
type CustomRuleCondition struct {
	Field         string   `json:"field"`
	Operator      string   `json:"operator"`
	Value         string   `json:"value"`
	Negate        bool     `json:"negate,omitempty"`
	CaseSensitive bool     `json:"case_sensitive,omitempty"`
	Transforms    []string `json:"transforms,omitempty"`
	// BodyScope restricts JSON-body matching to keys ("key"), values
	// ("value"), or both ("all", default). GUI rules only.
	BodyScope string `json:"body_scope,omitempty"`
}

// CustomRuleTuning is the config payload of a mode="tuning" rule:
// WHEN (Scope) — for TARGET components — the semantic engines are skipped,
// held to LOG, or have their scan mode switched. Engine "crs" and scan_mode
// crs_only are accepted from older clients and stores and have no effect.
type CustomRuleTuning struct {
	Scope  CustomRuleTuningScope  `json:"scope"`
	Target CustomRuleTuningTarget `json:"target"`
	Engine string                 `json:"engine"` // semantic | both (crs: accepted, ignored)
	Effect CustomRuleTuningEffect `json:"effect"`
}

type CustomRuleTuningScope struct {
	Logic      string                `json:"logic"` // and | or
	Conditions []CustomRuleCondition `json:"conditions"`
}

type CustomRuleTuningTarget struct {
	// Components are request parts this tuning applies to:
	// "request" (whole request), "query:<name>", "form:<field>",
	// "json:<pointer>", "header:<name>", "cookie:<name>",
	// "multipart:filename", "args" (all query+form args).
	Components []string `json:"components"`
	// Match selects how component names compare: exact | prefix | regex | any.
	Match string `json:"match"`
}

type CustomRuleTuningEffect struct {
	// SkipSemantic lists semantic engine names ("sql", "xss") or "*" to skip.
	SkipSemantic []string `json:"skip_semantic,omitempty"`
	// ScanMode switches the engine pipeline within this scope:
	// default | semantic_only | both | disabled (crs_only is stored as default).
	ScanMode string `json:"scan_mode,omitempty"`
	// Action "log" records a blocking detection of a matched request as LOG and lets the request
	// through. It is the only value a save accepts.
	Action string `json:"action,omitempty"`
	// Weaken is the key of a rule written before Action. It is read and never written: a save turns
	// it into Action "log" or drops it.
	Weaken *CustomRuleTuningWeaken `json:"weaken,omitempty"`
}

type CustomRuleTuningWeaken struct {
	// SensitivityDelta lowers the effective sensitivity floor
	// (e.g. -1 makes rules above userSensitivity-1 drop).
	SensitivityDelta int `json:"sensitivity_delta,omitempty"`
	// ScoreMultiplier scales engine scores within scope (0-1).
	ScoreMultiplier float64 `json:"score_multiplier,omitempty"`
	// ThresholdDelta raises decision thresholds within scope.
	ThresholdDelta *CustomRuleTuningThresholdDelta `json:"threshold_delta,omitempty"`
}

type CustomRuleTuningThresholdDelta struct {
	Block int `json:"block,omitempty"`
	Log   int `json:"log,omitempty"`
}
