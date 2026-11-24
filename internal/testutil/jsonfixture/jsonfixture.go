// Package jsonfixture compares a Go value with a JSON file kept in this
// repository. The files under test/frontend-fixtures are copied into the
// tests of the repositories that read them (the dashboard's are in
// wafio-cp-frontend, tests/fixtures/backend), so a change to the values here
// has to reach those copies.
package jsonfixture

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// UpdateEnv set to 1 makes Check rewrite the file from the Go value.
const UpdateEnv = "WAFIO_UPDATE_FRONTEND_FIXTURES"

// Check fails when the file at path differs from v encoded as indented JSON.
func Check(t *testing.T, path string, v any) {
	t.Helper()
	want, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	if os.Getenv(UpdateEnv) == "1" {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v: create it with %s=1", err, UpdateEnv)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s no longer matches the Go values: rewrite it with %s=1 and copy it to every repository that keeps a copy (wafio-cp-frontend tests/fixtures/backend/ for the dashboard)", path, UpdateEnv)
	}
}
