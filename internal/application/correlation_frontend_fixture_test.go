package application

import (
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/testutil/jsonfixture"
)

// The dashboard's chain editor lists the same fields, operators and
// destination scopes; its tests read the copy of this file.
func TestFrontendCorrelationFixture(t *testing.T) {
	// The validator names the scopes in the order the editor shows them.
	r := webShellChain()
	r.Stages[0].Conditions = append(r.Stages[0].Conditions,
		CorrelationCondition{Field: "dest_scope", Op: "eq", Value: "unknown"})
	err := ValidateCorrelationRule(r)
	if err == nil {
		t.Fatal("an unknown dest_scope passed validation")
	}
	m := regexp.MustCompile(`dest_scope must be one of ([a-z, ]+)$`).FindStringSubmatch(err.Error())
	if m == nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	scopes := strings.Split(m[1], ", ")
	if got, want := slices.Sorted(slices.Values(scopes)), slices.Sorted(maps.Keys(destScopes)); !slices.Equal(got, want) {
		t.Fatalf("the error names %v but destScopes holds %v", got, want)
	}
	jsonfixture.Check(t, "../../test/frontend-fixtures/correlation.json", map[string]any{
		"fields":      slices.Sorted(maps.Keys(correlationConditionFields)),
		"ops":         slices.Sorted(maps.Keys(correlationConditionOps)),
		"dest_scopes": scopes,
	})
}
