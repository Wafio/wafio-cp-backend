package setup

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A buffered write that cannot reach the file must surface as an error, so
// the caller never renames a truncated temp file over the live one.
func TestCloseBufferedReportsLostWrites(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "out.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	bw := bufio.NewWriter(f)
	_, _ = bw.WriteString("pending")
	_ = f.Close() // the flush now fails
	if err := closeBuffered(bw, f); err == nil {
		t.Fatal("closeBuffered: want the flush error, got nil")
	}

	g, err := os.Create(filepath.Join(t.TempDir(), "ok.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	bw = bufio.NewWriter(g)
	_, _ = bw.WriteString("data\n")
	if err := closeBuffered(bw, g); err != nil {
		t.Fatalf("closeBuffered: %v", err)
	}
	b, err := os.ReadFile(g.Name())
	if err != nil || string(b) != "data\n" {
		t.Fatalf("content = %q, %v", b, err)
	}
}

func TestWriteFromReaderInstallsContent(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "list.txt")
	n, err := writeFromReader(dst, strings.NewReader("a\nb\n"))
	if err != nil || n != 4 {
		t.Fatalf("writeFromReader = %d, %v", n, err)
	}
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file left behind: %v", err)
	}
}
