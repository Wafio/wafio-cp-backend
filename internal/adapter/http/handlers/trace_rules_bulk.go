package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// detectionRuleApplyBody is POST /hosts/apply/detection-rules.
type detectionRuleApplyBody struct {
	Targets hostTargetsReq `json:"targets"`
	Source  *struct {
		HostID  string   `json:"host_id"`
		RuleIDs []string `json:"rule_ids"`
	} `json:"source"`
	Rules        []detectionRuleInput `json:"rules"`
	OnConflict   string               `json:"on_conflict"`
	DryRun       bool                 `json:"dry_run"`
	SourceDigest string               `json:"source_digest"`
}

// rulesToCopy resolves the rules of a detection-rule apply: the named
// non-built-in rules of the source host, or inline bodies, each through
// Create's checks. The source host id is returned ("" for inline).
func (h *DetectionRulesHandler) rulesToCopy(ctx context.Context, projectID string, body detectionRuleApplyBody) ([]domain.DetectionRule, string, error) {
	if (body.Source == nil) == (body.Rules == nil) {
		return nil, "", bulkBadRequest("BAD_REQUEST", errors.New("name exactly one of source or rules"), "")
	}
	var inputs []detectionRuleInput
	sourceHost := ""
	if body.Source != nil {
		src := body.Source
		if len(src.RuleIDs) == 0 || len(src.RuleIDs) > maxApplyPolicyItems {
			return nil, "", bulkBadRequest("BAD_REQUEST", fmt.Errorf("rule_ids must name 1 to %d rules", maxApplyPolicyItems), "")
		}
		if _, err := uuid.Parse(src.HostID); err != nil {
			return nil, "", errApplyHostNotFound
		}
		if host, err := h.Repo.Host.GetByID(ctx, projectID, src.HostID); err != nil || host == nil {
			return nil, "", errApplyHostNotFound
		}
		seen := map[string]bool{}
		for _, id := range src.RuleIDs {
			if seen[id] {
				continue
			}
			seen[id] = true
			if _, err := uuid.Parse(id); err != nil {
				return nil, "", &bulkReqError{status: fiber.StatusNotFound, code: "RULE_NOT_FOUND", msg: "Rule not found on the source host."}
			}
			rule, err := h.Repo.DetectionRules.GetRule(ctx, id, projectID, src.HostID)
			if err != nil {
				return nil, "", &bulkReqError{status: fiber.StatusNotFound, code: "RULE_NOT_FOUND", msg: "Rule not found on the source host."}
			}
			if rule.BuiltIn {
				return nil, "", &bulkReqError{status: fiber.StatusBadRequest, code: "BUILTIN_RULE",
					msg: "Built-in rules exist on every host; enable or disable them per host."}
			}
			enabled, priority := rule.Enabled, rule.Priority
			inputs = append(inputs, detectionRuleInput{
				Name: rule.Name, Description: rule.Description, Enabled: &enabled, Action: rule.Action,
				Conditions: rule.Conditions, SeverityOverride: rule.SeverityOverride, Priority: &priority, Tags: rule.Tags,
			})
		}
		sourceHost = src.HostID
	} else {
		if len(body.Rules) == 0 || len(body.Rules) > maxApplyPolicyItems {
			return nil, "", bulkBadRequest("BAD_REQUEST", fmt.Errorf("rules must hold 1 to %d rules", maxApplyPolicyItems), "")
		}
		inputs = body.Rules
	}
	out := make([]domain.DetectionRule, 0, len(inputs))
	names := make([]string, 0, len(inputs))
	for _, in := range inputs {
		rule, rerr := validateDetectionRuleInput(in, projectID, "")
		if rerr != nil {
			return nil, "", bulkBadRequest("INVALID_RULE", rerr.err, "The rule is invalid.")
		}
		out = append(out, rule)
		names = append(names, rule.Name)
	}
	if err := checkCopyNames(names); err != nil {
		return nil, "", err
	}
	return out, sourceHost, nil
}

// Apply copies detection rules to many hosts, from a source host or inline
// bodies. Rules run at ingest, so hosts without an agent are applied too.
// Identity on the target is the exact name among its non-built-in rules.
//
//	POST /api/projects/:id/hosts/apply/detection-rules
func (h *DetectionRulesHandler) Apply(c *fiber.Ctx) error {
	projectID := c.Params("id")
	var body detectionRuleApplyBody
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "BAD_REQUEST"})
	}
	ids, label, err := checkTargets(body.Targets)
	if err != nil {
		return writeBulkError(c, err)
	}
	replace, err := parseOnConflict(body.OnConflict)
	if err != nil {
		return writeBulkError(c, err)
	}
	rules, sourceHost, err := h.rulesToCopy(c.UserContext(), projectID, body)
	if err != nil {
		return writeBulkError(c, err)
	}
	digest, err := checkSourceDigest(sourceHost, rules, body.SourceDigest)
	if err != nil {
		return writeBulkError(c, err)
	}
	actor := actorOf(c)
	run := &bulkApplyRun{repo: h.Repo, projectID: projectID, op: "detection_rules.copy", dryRun: body.DryRun, ids: ids, label: label, actor: actor,
		sourceDigest: digest,
		perHost: func(ctx context.Context, applyID string, t domain.ApplyTarget, now time.Time) hostApplyResult {
			return h.applyRulesToHost(ctx, projectID, t, sourceHost, rules, replace, body.DryRun, applyID, actor, now)
		}}
	return run.run(c)
}

// applyRulesToHost writes the rules to one host: built-ins are seeded first,
// a new name is created, an existing one skipped or replaced in place
// (keeping the rule id).
func (h *DetectionRulesHandler) applyRulesToHost(ctx context.Context, projectID string, t domain.ApplyTarget, sourceHost string,
	rules []domain.DetectionRule, replace, dryRun bool, applyID string, actor bulkActor, now time.Time) hostApplyResult {
	r := newApplyResult(t, now)
	switch {
	case t.Revoked:
		return r.skip("HOST_REVOKED")
	case sourceHost != "" && t.HostID == sourceHost:
		return r.skip("SOURCE_HOST")
	}
	if !dryRun {
		// One forwarding-filter refresh for the host after all of its
		// writes, not one per rule.
		var flush func()
		ctx, flush = h.Repo.DetectionRules.DeferChangeHook(ctx)
		defer flush()
		if err := h.Repo.DetectionRules.EnsureBuiltinRules(ctx, projectID, t.HostID); err != nil {
			slog.Warn("trace_rules_seed_failed", "project_id", projectID, "host_id", t.HostID, "err", err)
		}
	}
	current, err := h.Repo.DetectionRules.ListRulesUncached(ctx, projectID, t.HostID)
	if err != nil {
		return r.fail("INTERNAL_ERROR", "internal error")
	}
	byName := map[string]domain.DetectionRule{}
	for _, rule := range current {
		if _, dup := byName[rule.Name]; !rule.BuiltIn && !dup {
			byName[rule.Name] = rule
		}
	}
	created, replaced, existing := 0, 0, 0
	finish := func() hostApplyResult {
		r.Created, r.Replaced, r.Existing = intp(created), intp(replaced), intp(existing)
		return r
	}
	audit := func(action string, rule domain.DetectionRule) {
		auditDetached(ctx, h.Repo, repository.AuditEvent{
			ProjectID: projectID, ActorUserID: actor.userID,
			Action: action, TargetType: "trace_detection_rule", TargetID: rule.ID, TargetName: rule.Name,
			IP: actor.ip, UserAgent: actor.userAgent,
			MetadataJSON: map[string]any{"apply_id": applyID, "host_id": t.HostID},
		})
	}
	for _, rule := range rules {
		rule.ProjectID, rule.HostID = projectID, t.HostID
		if ex, ok := byName[rule.Name]; ok {
			if !replace {
				existing++
				continue
			}
			replaced++
			if dryRun {
				continue
			}
			rule.ID = ex.ID
			updated, err := h.Repo.DetectionRules.UpdateRule(ctx, rule)
			if err != nil {
				replaced--
				slog.Error("bulk_rule_replace_failed", "host_id", t.HostID, "err", err)
				return finish().fail("INTERNAL_ERROR", "internal error")
			}
			audit(repository.AuditTraceRuleUpdated, updated)
			continue
		}
		created++
		if dryRun {
			continue
		}
		saved, err := h.Repo.DetectionRules.CreateRule(ctx, rule)
		if err != nil {
			created--
			slog.Error("bulk_rule_create_failed", "host_id", t.HostID, "err", err)
			return finish().fail("INTERNAL_ERROR", "internal error")
		}
		audit(repository.AuditTraceRuleCreated, saved)
	}
	switch {
	case created+replaced == 0:
		r.Status = applyUnchanged
	case dryRun:
		r.Status = applyWouldApply
	default:
		r.Status = applyApplied
	}
	return finish()
}
