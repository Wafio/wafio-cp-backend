package repository

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The tenant-isolation fix added `JOIN agents a` to the tenant-scoped WAF queries so that
// waf_decisions, which has no project_id of its own, could be filtered by one.
// Two of those queries kept their original unqualified SELECT list. Both tables
// have an `id` column, so PostgreSQL answered:
//
//	ERROR: column reference "id" is ambiguous
//
// The dashboard showed "query failed" and nothing else. It went unnoticed
// because it cannot be caught without a database: the SQL is a string, so it
// compiles, and every unit test passed.
//
// This reads the SQL instead. It is not a substitute for running the queries --
// TestWAFQueriesRunAgainstPostgres below does that when a database is available
// -- but it runs everywhere, including in CI with no database, which is where
// the regression would otherwise slip through again.
func TestJoinedQueriesQualifyAmbiguousColumns(t *testing.T) {
	// Columns that exist on both waf_decisions and agents. Anything here must
	// carry a table alias once the two are joined.
	ambiguous := []string{"id"}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}

	// A backtick-quoted SQL literal that joins agents.
	stmt := regexp.MustCompile("(?s)`([^`]*JOIN\\s+agents[^`]*)`")

	var findings []string
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range stmt.FindAllStringSubmatchIndex(string(src), -1) {
			sql := string(src)[m[2]:m[3]]
			sel := selectList(sql)
			if sel == "" {
				continue
			}
			for _, col := range ambiguous {
				// Unqualified: the name not preceded by a dot or word character.
				bare := regexp.MustCompile(`(^|[\s,(])` + col + `\b`)
				if bare.MatchString(sel) {
					line := strings.Count(string(src)[:m[2]], "\n") + 1
					findings = append(findings,
						path+":"+strconv.Itoa(line)+": SELECT uses bare "+col+
							" in a query that joins agents; both tables have it")
				}
			}
		}
	}

	if len(findings) > 0 {
		t.Errorf("a joined query must qualify columns that exist on both tables, "+
			"or PostgreSQL refuses it at runtime while the Go code compiles fine:\n  %s",
			strings.Join(findings, "\n  "))
	}
}

// selectList returns the text between SELECT and the FROM that closes it.
//
// FROM is matched as a word, not as " FROM " -- in these queries it usually
// begins a line, so requiring surrounding spaces made this return "" for almost
// every statement and the check silently examined nothing. The self-test below
// exists because a detector that quietly matches nothing looks exactly like a
// detector that finds no problems.
var selectFrom = regexp.MustCompile(`(?is)\bSELECT\b(.*?)\bFROM\b`)

func selectList(sql string) string {
	m := selectFrom.FindStringSubmatch(sql)
	if m == nil {
		return ""
	}
	return m[1]
}

// The detector must fail on the SQL that actually shipped, or it is proving
// nothing. This is ListDecisionsForApp as it was when the dashboard broke.
func TestQualificationCheckDetectsTheShippedBug(t *testing.T) {
	shipped := `
		SELECT id, agent_id, COALESCE(app_id::text,''), host
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id
		WHERE d.app_id = $1 AND a.project_id = $2`
	sel := selectList(shipped)
	if !regexp.MustCompile(`(^|[\s,(])id\b`).MatchString(sel) {
		t.Fatal("the check does not flag the exact SELECT list that failed in production")
	}

	fixed := `
		SELECT d.id, d.agent_id, COALESCE(d.app_id::text,''), d.host
		FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id`
	if regexp.MustCompile(`(^|[\s,(])id\b`).MatchString(selectList(fixed)) {
		t.Fatal("the check flags the corrected form, which would make it noise")
	}
}
