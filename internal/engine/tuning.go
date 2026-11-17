package engine

// Engine tuning rules: ResolveTuningPlan merges
// all scope-matching tuning rules (stable order: priority, created_at, id)
// into one per-request TuningPlan the pipeline consults at each engine stage.
// Later (lower priority) matching rules merge additively, except ScanMode:
// the highest-priority matching rule's ScanMode wins.

import (
	"strings"
)

// ResolveTuningPlan resolves all enabled tuning rules against the request
// context. Returns nil when no rule's scope matches (all methods are
// nil-receiver safe).
func ResolveTuningPlan(rules []TuningRule, ctx *WAFRuleContext) *TuningPlan {
	if len(rules) == 0 {
		return nil
	}
	var plan *TuningPlan
	for _, r := range sortByOrder(rules, func(r TuningRule) ruleOrder {
		return ruleOrder{priority: r.Priority, createdAt: r.CreatedAt, id: r.ID}
	}) {
		if !r.Enabled {
			continue
		}
		if !matchTuningScope(&r.Scope, ctx) {
			continue
		}
		if plan == nil {
			plan = &TuningPlan{SkipSemanticEngines: make(map[string]bool, 4)}
		}
		plan.MatchedRuleIDs = append(plan.MatchedRuleIDs, r.ID)

		if plan.ScanMode == "" && r.Effect.ScanMode != "" {
			plan.ScanMode = CanonicalScanMode(r.Effect.ScanMode)
			applyScanMode(plan, plan.ScanMode)
		}

		// Engine gating: a rule scoped to the removed rule set engine
		// ("crs", read only from stored rules; the control plane drops them
		// from bundles) merges neither semantic skips nor weakening. The gated effect copy
		// is merged by the shared ApplyTuningEffectToPlan core (the
		// slice/pointer fields are copied by value; the originals stay
		// untouched).
		eff := r.Effect
		if strings.EqualFold(strings.TrimSpace(r.Engine), "crs") {
			eff.SkipSemantic = nil
			eff.Weaken = nil
		}
		plan = ApplyTuningEffectToPlan(plan, eff, r.Target)
	}
	return plan
}

// ApplyTuningEffectToPlan merges one tuning effect (+ its target) into a
// plan, creating the plan when nil. It is the shared merge core of
// ResolveTuningPlan and of path-exception tuning (PathTuningConfig), with
// identical semantics: semantic skip lists union additively, weaken takes
// the strongest weakening (min sensitivity delta, min positive multiplier,
// max threshold raise), and the target is appended only when it has
// components — a component-less target must not restrict skips once a matched
// variable is surfaced. effect.ScanMode is deliberately IGNORED: scan mode is
// resolved by ResolveTuningPlan (first matching rule wins) and, on the path
// side, owned by the path rule's inspection_off switch: a path tuning
// scan_mode would be dead config and is rejected at validation.
func ApplyTuningEffectToPlan(plan *TuningPlan, effect TuningEffect, target TuningTarget) *TuningPlan {
	if plan == nil {
		plan = &TuningPlan{SkipSemanticEngines: make(map[string]bool, 4)}
	}
	if len(target.Components) > 0 {
		plan.Targets = append(plan.Targets, target)
	}
	mergeSemanticEffect(plan, &effect)
	return plan
}

// matchTuningScope applies GUI-rule condition logic to a tuning scope. An
// empty scope (no conditions) matches every request.
func matchTuningScope(s *TuningScope, ctx *WAFRuleContext) bool {
	if len(s.Conditions) == 0 {
		return true
	}
	logic := strings.ToLower(strings.TrimSpace(s.Logic))
	if logic != "or" {
		logic = "and"
	}
	for i := range s.Conditions {
		match := evalCondition(&s.Conditions[i], ctx)
		if logic == "or" && match {
			return true
		}
		if logic == "and" && !match {
			return false
		}
	}
	return logic == "and"
}

// CanonicalScanMode reads a tuning scan_mode as the pipeline does: trimmed, lower case, with crs_only
// and semantic_only (rules stored before the rule set engine was removed) read as default.
func CanonicalScanMode(mode string) string {
	m := strings.ToLower(strings.TrimSpace(mode))
	if m == "crs_only" || m == "semantic_only" {
		return "default"
	}
	return m
}

// applyScanMode applies the unconditional scan-mode effects:
//
//	disabled → skip the semantic stage entirely (inspection off)
//	both     → clear all skips (later additive rules may re-add)
func applyScanMode(p *TuningPlan, mode string) {
	switch mode {
	case "disabled":
		p.SkipSemanticAll = true
	case "both":
		p.SkipSemanticAll = false
		p.SkipSemanticEngines = make(map[string]bool)
	}
	// "default" (and anything else) → no effect
}

func mergeSemanticEffect(p *TuningPlan, e *TuningEffect) {
	for _, s := range e.SkipSemantic {
		s = strings.ToLower(strings.TrimSpace(s))
		switch s {
		case "":
			continue
		case "*":
			p.SkipSemanticAll = true
		default:
			p.SkipSemanticEngines[s] = true
		}
	}
	if w := e.Weaken; w != nil {
		// strongest weakening wins: min positive multiplier, max threshold
		// raise. sensitivity_delta is accepted and ignored: no engine gates
		// on a sensitivity level.
		if w.ScoreMultiplier > 0 {
			if p.ScoreMultiplier == 0 || w.ScoreMultiplier < p.ScoreMultiplier {
				p.ScoreMultiplier = w.ScoreMultiplier
			}
		}
		if d := w.ThresholdDelta; d != nil {
			p.BlockDelta = max(p.BlockDelta, d.Block)
			p.LogDelta = max(p.LogDelta, d.Log)
		}
	}
}

// ---------------------------------------------------------------------------
// TuningPlan accessors (all nil-receiver safe)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// target matching
// ---------------------------------------------------------------------------

// pointerToDottedName converts "/a/b" (RFC 6901, ~0/~1 escaped) to "a.b".
func pointerToDottedName(pointer string) string {
	if pointer == "" {
		return ""
	}
	p := strings.TrimPrefix(pointer, "/")
	p = strings.ReplaceAll(p, "~1", "/")
	p = strings.ReplaceAll(p, "~0", "~")
	return strings.ReplaceAll(p, "/", ".")
}

// splitTargetComponent splits a tuning target component into the name its
// match mode compares and its class ("query", "form", "json", ...; "" for an
// unprefixed bare name, tolerated at eval time). JSON pointers become dotted
// names. whole reports the class-wide components ("", "request", "args",
// "multipart:filename"), which carry no name.
func splitTargetComponent(comp string) (compName, compClass string, whole bool) {
	lower := strings.ToLower(comp)
	switch lower {
	case "", "request", "args", "multipart:filename":
		return "", "", true
	}
	for _, prefix := range [...]string{"query:", "form:", "json:", "header:", "cookie:", "multipart:filename:", "multipart:"} {
		if strings.HasPrefix(lower, prefix) {
			compName = comp[len(prefix):]
			compClass = strings.TrimSuffix(prefix, ":")
			break
		}
	}
	if compName == "" {
		return comp, "", false
	}
	if strings.HasPrefix(compName, "/") {
		compName = pointerToDottedName(compName)
	}
	return compName, compClass, false
}

// targetComponentName is the name part of a named target component (see
// splitTargetComponent); ok is false for a class-wide component.
func targetComponentName(comp string) (name string, ok bool) {
	name, _, whole := splitTargetComponent(comp)
	return name, !whole
}
