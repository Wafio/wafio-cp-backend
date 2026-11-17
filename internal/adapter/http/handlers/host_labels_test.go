package handlers

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

func TestHostLabelKeyValidation(t *testing.T) {
	for _, tc := range []struct {
		key string
		ok  bool
	}{
		{"env", true}, {"team.edge", true}, {"k8s.io/zone", true}, {"a-b_c", true}, {"9lives", true},
		{strings.Repeat("a", 63), true}, {strings.Repeat("a", 64), false},
		{"", false}, {"-env", false}, {".env", false}, {"env key", false}, {"env=prod", false}, {"ünïcode", false},
	} {
		if err := validateHostLabelKey(tc.key); (err == nil) != tc.ok {
			t.Errorf("key %q: err=%v want ok=%v", tc.key, err, tc.ok)
		}
	}
}

func TestHostLabelValueValidation(t *testing.T) {
	for _, tc := range []struct {
		value, want string
		ok          bool
	}{
		{"  prod  ", "prod", true},
		{"", "", true},
		{strings.Repeat("é", 128), strings.Repeat("é", 128), true},
		{strings.Repeat("v", 129), "", false},
		{"a\x00b", "", false},
		{"tab\tinside", "", false},
		{"del\x7f", "", false},
		{"bad\xffutf8", "", false},
		{"c1\u009bx", "", false},
		{"rtl\u202ex", "", false},
		{"esc\x1b]0;t\x07", "", false},
		{"東京-1", "東京-1", true},
	} {
		got, err := normalizeHostLabelValue("k", tc.value)
		if (err == nil) != tc.ok || (tc.ok && got != tc.want) {
			t.Errorf("value %q: got %q err=%v", tc.value, got, err)
		}
	}
}

func TestValidateHostLabelsForCreate(t *testing.T) {
	if out, code, err := validateHostLabels(map[string]string{"env": " prod "}); err != nil || code != "" || out["env"] != "prod" {
		t.Fatalf("valid labels: %v %q %v", out, code, err)
	}
	if _, code, err := validateHostLabels(map[string]string{"bad key": "x"}); err == nil || code != "INVALID_LABELS" {
		t.Fatalf("bad key: %q %v", code, err)
	}
	many := map[string]string{}
	for i := 0; i <= domain.MaxHostLabels; i++ {
		many[fmt.Sprintf("k%d", i)] = "v"
	}
	if _, code, err := validateHostLabels(many); err == nil || code != "TOO_MANY_LABELS" {
		t.Fatalf("33 labels: %q %v", code, err)
	}
	if out, _, err := validateHostLabels(nil); err != nil || out == nil {
		t.Fatalf("no labels: %v %v", out, err)
	}
}

func TestCheckLabelEdit(t *testing.T) {
	if _, _, err := checkLabelEdit(nil, nil); err == nil {
		t.Fatal("empty edit accepted")
	}
	if _, _, err := checkLabelEdit(map[string]string{"env": "x"}, []string{"env"}); err == nil {
		t.Fatal("key in set and remove accepted")
	}
	if _, _, err := checkLabelEdit(nil, []string{"bad key"}); err == nil {
		t.Fatal("invalid remove key accepted")
	}
	if _, _, err := checkLabelEdit(map[string]string{"env": strings.Repeat("v", 129)}, nil); err == nil {
		t.Fatal("long value accepted")
	}
	set, rm, err := checkLabelEdit(map[string]string{"env": " prod "}, []string{"old", "old"})
	if err != nil || set["env"] != "prod" || len(rm) != 1 {
		t.Fatalf("valid edit: %v %v %v", set, rm, err)
	}
}

func TestApplyLabelEditCap(t *testing.T) {
	full := map[string]string{}
	for i := 0; i < domain.MaxHostLabels; i++ {
		full[fmt.Sprintf("k%d", i)] = "v"
	}
	current := []domain.HostLabels{{ID: "h1", Labels: full}, {ID: "h2", Labels: map[string]string{"old": "x"}}}
	_, err := applyLabelEdit(current, map[string]string{"new": "v"}, nil)
	var tooMany *tooManyLabelsError
	if !errors.As(err, &tooMany) || len(tooMany.hostIDs) != 1 || tooMany.hostIDs[0] != "h1" {
		t.Fatalf("cap: %v", err)
	}
	// Removing one first keeps the full host at 32.
	next, err := applyLabelEdit(current, map[string]string{"new": "v"}, []string{"k0", "old"})
	if err != nil || len(next[0].Labels) != domain.MaxHostLabels || next[1].Labels["new"] != "v" || next[1].Labels["old"] != "" {
		t.Fatalf("edit: %+v %v", next, err)
	}
	if current[1].Labels["old"] != "x" {
		t.Fatal("edit changed its input")
	}
}

func TestParseTargetHostIDs(t *testing.T) {
	id := uuid.NewString()
	many := make([]string, domain.MaxApplyTargets+1)
	for i := range many {
		many[i] = uuid.NewString()
	}
	for _, tc := range []struct {
		name string
		ids  []string
		ok   bool
	}{
		{"none", nil, false},
		{"empty", []string{}, false},
		{"one", []string{id}, true},
		{"1001", many, false},
		{"1000", many[:domain.MaxApplyTargets], true},
		{"duplicate", []string{id, id}, false},
		{"duplicate by case", []string{id, strings.ToUpper(id)}, false},
		{"not a uuid", []string{"fleet"}, false},
		{"braced uuid", []string{"{" + id + "}"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseTargetHostIDs(tc.ids); (err == nil) != tc.ok {
				t.Fatalf("err=%v want ok=%v", err, tc.ok)
			}
		})
	}
}
