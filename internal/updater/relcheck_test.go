package updater

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verifies the artefacts about to be published against the key compiled into
// this binary. Running it before an upload is the difference between shipping a
// release and shipping one nobody can install.
func TestPublishedArtifactsVerify(t *testing.T) {
	const version = "v1.4.0"
	files, _ := filepath.Glob("../../dist/*-" + version + "-linux-amd64.tar.gz")
	if len(files) == 0 {
		t.Skip("no v1.4.0 artefacts built")
	}
	for _, f := range files {
		sigRaw, err := os.ReadFile(f + ".sig")
		if err != nil {
			t.Errorf("%s has no signature beside it: %v", filepath.Base(f), err)
			continue
		}
		sum, err := fileSHA256ForTest(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyRelease(version, sum, strings.TrimSpace(string(sigRaw))); err != nil {
			t.Errorf("%s does NOT verify against the compiled-in key: %v", filepath.Base(f), err)
			continue
		}
		t.Logf("%s verifies (%s)", filepath.Base(f), sum[:16])
	}
}
