package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Each per-chunk index names the migration that introduces it: a renumbered
// migration must move sinceVersion with it, or `migrate up` never builds the
// index on a hypertable.
func TestPerChunkIndexVersionsMatchMigrations(t *testing.T) {
	for _, ix := range perChunkIndexes {
		matches, err := filepath.Glob(filepath.Join("..", "..", "migrations", fmt.Sprintf("%06d_*.up.sql", ix.sinceVersion)))
		if err != nil || len(matches) != 1 {
			t.Fatalf("%s: no single migration %06d (%v, %v)", ix.name, ix.sinceVersion, matches, err)
		}
		body, err := os.ReadFile(matches[0])
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), ix.name) {
			t.Errorf("%s: migration %s does not mention the index", ix.name, filepath.Base(matches[0]))
		}
	}
}
