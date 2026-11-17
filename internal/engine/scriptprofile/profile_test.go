// Package scriptprofile_test pins shared/script/profile.json to the sandbox the
// engine runs script rules in. It lives apart from internal/engine because the oracle generators
// there read every string literal of that directory's test files.
package scriptprofile_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/engine"
)

var update = flag.Bool("update", false, "rewrite shared/script/profile.json from the engine")

func TestScriptProfileMatchesEngine(t *testing.T) {
	path := filepath.Join("..", "..", "..", "shared", "script", "profile.json")
	want := engine.SandboxProfile()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, want, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path) //nolint:gosec // G304: fixed repository path
	if err != nil {
		t.Fatalf("%v (go test ./internal/engine/scriptprofile -update writes it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from the engine sandbox; run: go test ./internal/engine/scriptprofile -update\nfile:\n%s\nengine:\n%s", path, got, want)
	}
}
