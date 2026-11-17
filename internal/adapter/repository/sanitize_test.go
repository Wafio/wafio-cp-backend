package repository

import (
	"strings"
	"testing"
	"unicode/utf8"
)

const nul = "\x00"

func TestSanitizeStoredTextReplacesNUL(t *testing.T) {
	got := sanitizeStoredText("/etc/passwd" + nul + ".jpg")
	if strings.ContainsRune(got, 0) {
		t.Fatalf("NUL survived: %q", got)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("result is not valid UTF-8: %q", got)
	}
}

// The reason NUL is replaced rather than stripped. A null-byte truncation
// attack reads as an ordinary image request once the NUL is deleted, so a
// stripping sanitiser would write a request nobody made into the audit trail.
func TestSanitizeStoredTextDoesNotForgeABenignPath(t *testing.T) {
	got := sanitizeStoredText("/etc/passwd" + nul + ".jpg")
	if got == "/etc/passwd.jpg" {
		t.Fatal("stripping the NUL turned an attack into a plausible image request")
	}
	if !strings.HasPrefix(got, "/etc/passwd") || !strings.HasSuffix(got, ".jpg") {
		t.Errorf("evidence on either side of the NUL was lost: %q", got)
	}
}

func TestSanitizeStoredTextAlsoFixesInvalidUTF8(t *testing.T) {
	// A decision arriving over the HTTP ingest path never passed the agent's
	// proto sanitiser, so this layer cannot assume the bytes are already valid.
	got := sanitizeStoredText("/search?q=\xff\xfe")
	if !utf8.ValidString(got) {
		t.Fatalf("invalid UTF-8 survived: %q", got)
	}
}

func TestSanitizeStoredTextLeavesCleanInputAlone(t *testing.T) {
	for _, s := range []string{"", "/index.php", "' OR 1=1--", "日本語", "Rp1.000"} {
		if got := sanitizeStoredText(s); got != s {
			t.Errorf("sanitizeStoredText(%q) = %q, want unchanged", s, got)
		}
	}
}

func TestSanitizeStoredSliceAndMap(t *testing.T) {
	cats := []string{"sqli", "xss" + nul, "lfi" + nul}
	got := sanitizeStoredSlice(cats)
	for _, c := range got {
		if strings.ContainsRune(c, 0) {
			t.Errorf("NUL survived in categories: %q", got)
		}
	}
	if got[0] != "sqli" {
		t.Errorf("clean element altered: %q", got[0])
	}
	if cats[1] != "xss"+nul {
		t.Error("sanitizeStoredSlice mutated its input")
	}

	// jsonb rejects a NUL in an object key exactly as it does in a value.
	hdr := map[string]string{"X-Bad" + nul: "v", "X-Ok": "clean" + nul}
	m := sanitizeStoredMap(hdr)
	for k, v := range m {
		if strings.ContainsRune(k, 0) || strings.ContainsRune(v, 0) {
			t.Errorf("NUL survived in headers: %q=%q", k, v)
		}
	}
	if len(hdr) != 2 || hdr["X-Ok"] != "clean"+nul {
		t.Error("sanitizeStoredMap mutated its input")
	}
	if sanitizeStoredMap(nil) != nil {
		t.Error("nil map should stay nil")
	}
}

// A NUL anywhere on the decision must not reach COPY, because COPY takes the
// whole batch down with it.
func TestSanitizeDecisionCoversEveryStoredString(t *testing.T) {
	d := WAFDecision{
		Host: "h" + nul, Method: "GET" + nul, URI: "/u" + nul,
		RemoteAddr: "1.2.3.4" + nul, CountryCode: "ID" + nul,
		UserAgent: "ua" + nul, ContentType: "ct" + nul, Action: "block" + nul,
		CWE: "CWE-89" + nul, MatchDetail: "md" + nul, AnalyzeMethod: "am" + nul,
		BodyPreview: "bp" + nul, MatchSource: "ms" + nul, RequestBody: "rb" + nul,
		QueryParams: "qp" + nul, PayloadType: "pt" + nul, Coverage: "body_decompress_error" + nul,
		Categories:     []string{"c" + nul},
		RequestHeaders: map[string]string{"k" + nul: "v" + nul},
	}
	got := sanitizeDecision(d)

	for name, v := range map[string]string{
		"Host": got.Host, "Method": got.Method, "URI": got.URI,
		"RemoteAddr": got.RemoteAddr, "CountryCode": got.CountryCode,
		"UserAgent": got.UserAgent, "ContentType": got.ContentType,
		"Action": got.Action, "CWE": got.CWE, "MatchDetail": got.MatchDetail,
		"AnalyzeMethod": got.AnalyzeMethod, "BodyPreview": got.BodyPreview,
		"MatchSource": got.MatchSource, "RequestBody": got.RequestBody,
		"QueryParams": got.QueryParams, "PayloadType": got.PayloadType,
		"Coverage": got.Coverage,
	} {
		if strings.ContainsRune(v, 0) {
			t.Errorf("%s still holds a NUL: %q", name, v)
		}
	}
	if strings.ContainsRune(got.Categories[0], 0) {
		t.Error("Categories still holds a NUL")
	}
	for k, v := range got.RequestHeaders {
		if strings.ContainsRune(k, 0) || strings.ContainsRune(v, 0) {
			t.Errorf("RequestHeaders still holds a NUL: %q=%q", k, v)
		}
	}
}

// Coverage arrives as free text on the legacy HTTP ingest: it is capped at a
// rune boundary so a hostile agent cannot store an unbounded string.
func TestSanitizeDecisionCapsCoverage(t *testing.T) {
	long := strings.Repeat("a", maxStoredCoverageLen-1) + "é" + "tail"
	got := sanitizeDecision(WAFDecision{Coverage: long}).Coverage
	if len(got) > maxStoredCoverageLen || !utf8.ValidString(got) {
		t.Fatalf("coverage not capped at a rune boundary: len=%d valid=%v", len(got), utf8.ValidString(got))
	}
	if got != strings.Repeat("a", maxStoredCoverageLen-1) {
		t.Fatalf("unexpected truncation: %q", got[len(got)-8:])
	}
	if short := "field_cap,body_binary"; sanitizeDecision(WAFDecision{Coverage: short}).Coverage != short {
		t.Fatal("a short coverage value must pass through unchanged")
	}
}
