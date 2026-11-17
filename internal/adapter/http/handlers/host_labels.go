package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/validate"
)

// Host labels are selection metadata: no stored policy refers to a
// label, so editing labels never changes what a host enforces.

// hostLabelKeyRe is the dashboard's LABEL_KEY (hosts/host-info.ts).
var hostLabelKeyRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,62}$`)

// errInvalidLabel is a refused label key or value (400 INVALID_LABELS).
type errInvalidLabel struct{ msg string }

func (e errInvalidLabel) Error() string { return e.msg }

// validateHostLabelKey checks one label key.
func validateHostLabelKey(k string) error {
	if !hostLabelKeyRe.MatchString(k) {
		return errInvalidLabel{fmt.Sprintf("label key %q is invalid: 1-63 letters, digits, '.', '_', '/' or '-', starting with a letter or digit", clipLabel(k))}
	}
	return nil
}

// normalizeHostLabelValue trims a label value and checks it: at most 128
// characters, no control characters.
func normalizeHostLabelValue(k, v string) (string, error) {
	v = strings.TrimSpace(v)
	if !utf8.ValidString(v) || utf8.RuneCountInString(v) > domain.MaxHostLabelValueLen {
		return "", errInvalidLabel{fmt.Sprintf("label %q: the value must be valid text of at most %d characters", clipLabel(k), domain.MaxHostLabelValueLen)}
	}
	if !validate.PlainText(v) {
		return "", errInvalidLabel{fmt.Sprintf("label %q: the value must not contain control, formatting or bidi characters", clipLabel(k))}
	}
	return v, nil
}

// validateHostLabels checks and normalises a whole label set (POST /hosts):
// keys, values and the 32-label cap. It returns the trimmed set.
func validateHostLabels(labels map[string]string) (map[string]string, string, error) {
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		if err := validateHostLabelKey(k); err != nil {
			return nil, "INVALID_LABELS", err
		}
		nv, err := normalizeHostLabelValue(k, v)
		if err != nil {
			return nil, "INVALID_LABELS", err
		}
		out[k] = nv
	}
	if len(out) > domain.MaxHostLabels {
		return nil, "TOO_MANY_LABELS", fmt.Errorf("a host carries at most %d labels", domain.MaxHostLabels)
	}
	return out, "", nil
}

func clipLabel(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

// parseTargetHostIDs checks a host id list: 1–1,000 unique UUIDs.
func parseTargetHostIDs(ids []string) ([]string, error) {
	if len(ids) == 0 || len(ids) > domain.MaxApplyTargets {
		return nil, fmt.Errorf("host_ids must name 1 to %d hosts", domain.MaxApplyTargets)
	}
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		u, err := uuid.Parse(id)
		if err != nil || len(id) != 36 {
			return nil, errors.New("host_ids must be host ids (UUIDs)")
		}
		canon := u.String()
		if seen[canon] {
			return nil, errors.New("host_ids must not repeat a host")
		}
		seen[canon] = true
		out = append(out, canon)
	}
	return out, nil
}

type hostLabelsBody struct {
	HostIDs []string          `json:"host_ids"`
	Set     map[string]string `json:"set"`
	Remove  []string          `json:"remove"`
}

// tooManyLabelsError: the edit would leave hosts with more than 32 labels.
type tooManyLabelsError struct{ hostIDs []string }

func (e *tooManyLabelsError) Error() string {
	return fmt.Sprintf("%d hosts would carry more than %d labels", len(e.hostIDs), domain.MaxHostLabels)
}

// UpdateLabels sets and removes labels on many hosts at once: all or
// nothing, one transaction, one host.labels_updated audit row per host whose
// labels changed. Revoked hosts are editable (labels are metadata).
//
//	POST /api/projects/:id/hosts/labels
func (h *HostsHandler) UpdateLabels(c *fiber.Ctx) error {
	projectID := c.Params("id")
	var body hostLabelsBody
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "BAD_REQUEST"})
	}
	ids, err := parseTargetHostIDs(body.HostIDs)
	if err != nil {
		return invalidInput(c, "INVALID_TARGETS", err)
	}
	set, remove, err := checkLabelEdit(body.Set, body.Remove)
	if err != nil {
		return invalidInput(c, "INVALID_LABELS", err)
	}
	edit := func(current []domain.HostLabels) ([]domain.HostLabels, error) {
		return applyLabelEdit(current, set, remove)
	}
	userID, _ := c.Locals(auth.UserIDKey).(string)
	actor := domain.AuditActor{UserID: userID, IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent())}
	result, updated, err := h.Repo.HostFleet.UpdateLabelsAudited(c.UserContext(), projectID, ids, edit, actor, uuid.NewString())
	var tooMany *tooManyLabelsError
	switch {
	case errors.Is(err, domain.ErrHostNotFound):
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Host not found.", "code": "HOST_NOT_FOUND"})
	case errors.As(err, &tooMany):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":    fmt.Sprintf("A host carries at most %d labels.", domain.MaxHostLabels),
			"code":     "TOO_MANY_LABELS",
			"host_ids": tooMany.hostIDs,
		})
	case err != nil:
		slog.Error("host_labels_update_failed", "project_id", projectID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error", "code": "INTERNAL_ERROR"})
	}
	return c.JSON(fiber.Map{"ok": true, "updated": updated, "unchanged": len(result) - updated, "hosts": result})
}

// checkLabelEdit validates a set/remove pair: at least one non-empty, every
// key valid, no key in both; values are trimmed.
func checkLabelEdit(set map[string]string, remove []string) (map[string]string, []string, error) {
	if len(set) == 0 && len(remove) == 0 {
		return nil, nil, errInvalidLabel{"set or remove must name at least one label"}
	}
	if len(remove) > domain.MaxApplyTargets {
		return nil, nil, errInvalidLabel{"too many labels in one edit"}
	}
	out := make(map[string]string, len(set))
	for k, v := range set {
		if err := validateHostLabelKey(k); err != nil {
			return nil, nil, err
		}
		nv, err := normalizeHostLabelValue(k, v)
		if err != nil {
			return nil, nil, err
		}
		out[k] = nv
	}
	rm := make([]string, 0, len(remove))
	for _, k := range remove {
		if err := validateHostLabelKey(k); err != nil {
			return nil, nil, err
		}
		if _, both := out[k]; both {
			return nil, nil, errInvalidLabel{fmt.Sprintf("label %q is both set and removed", k)}
		}
		if !slices.Contains(rm, k) {
			rm = append(rm, k)
		}
	}
	return out, rm, nil
}

// applyLabelEdit computes every host's new labels; a host that would carry
// more than 32 labels fails the whole edit.
func applyLabelEdit(current []domain.HostLabels, set map[string]string, remove []string) ([]domain.HostLabels, error) {
	next := make([]domain.HostLabels, len(current))
	var over []string
	for i, hl := range current {
		labels := maps.Clone(hl.Labels)
		if labels == nil {
			labels = map[string]string{}
		}
		for _, k := range remove {
			delete(labels, k)
		}
		maps.Copy(labels, set)
		if len(labels) > domain.MaxHostLabels {
			over = append(over, hl.ID)
		}
		next[i] = domain.HostLabels{ID: hl.ID, Name: hl.Name, Labels: labels}
	}
	if len(over) > 0 {
		return nil, &tooManyLabelsError{hostIDs: over}
	}
	return next, nil
}
