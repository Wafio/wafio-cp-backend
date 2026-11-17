// Package installertest finds the public installer for the tests that run parts of it against this repository.
package installertest

import (
	"os"
	"path/filepath"
	"testing"
)

// Source returns the path and the text of the public installer, deploy/install.sh of the wafio-release repository:
// the file WAFIO_INSTALLER names, or the one in a wafio-release checkout next to this repository. The test is skipped
// when neither exists, and fails when WAFIO_INSTALLER names a file that cannot be read.
func Source(t *testing.T) (string, []byte) {
	t.Helper()
	path := os.Getenv("WAFIO_INSTALLER")
	if path == "" {
		root, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		for {
			if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
				break
			}
			if filepath.Dir(root) == root {
				t.Fatal("no go.mod above the test directory")
			}
			root = filepath.Dir(root)
		}
		path = filepath.Join(filepath.Dir(root), "wafio-release", "deploy", "install.sh")
		if _, err := os.Stat(path); err != nil {
			t.Skip("no installer: set WAFIO_INSTALLER, or check out wafio-release next to this repository")
		}
	}
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, src
}
