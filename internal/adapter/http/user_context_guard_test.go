package httpadapter

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// passesFiberContext matches c.Context() handed to a call as an argument --
// the shape of a repository call on fasthttp's RequestCtx, which carries no
// deadline. Uses such as c.Context().SetBodyStreamWriter or
// c.Context().Done() in the SSE plumbing do not match.
var passesFiberContext = regexp.MustCompile(`[(,]\s*c\.Context\(\)\s*[,)]`)

// Request work runs on c.UserContext(), which requestContext gives a
// deadline; c.Context() has none and outlives a disconnected client.
func TestHTTPAdapterPassesUserContextNotFiberContext(t *testing.T) {
	var offenders []string
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if passesFiberContext.MatchString(line) {
				offenders = append(offenders, path+":"+strconv.Itoa(i+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("c.Context() passed to a call; use c.UserContext():\n  %s", strings.Join(offenders, "\n  "))
	}
}
