package engine_test

import (
	"bytes"
	"mime/multipart"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/engine"
)

func TestParseRequestBody_JSONNested(t *testing.T) {
	p := engine.ParseRequestBody("application/json", []byte(`{"a":{"b":["x",1,true]},"n":null,"top":"str"}`))
	if p.ParseError != "" {
		t.Fatalf("unexpected ParseError: %q", p.ParseError)
	}
	if p.ContentType != "application/json" {
		t.Errorf("ContentType = %q, want application/json", p.ContentType)
	}
	want := map[string]string{
		"json.top":   "str",
		"json.a.b.0": "x",
		"json.a.b.1": "1",
		"json.a.b.2": "true",
	}
	if len(p.JSONFlat) != len(want) { // null produces no entry
		t.Fatalf("JSONFlat = %v, want %d entries", p.JSONFlat, len(want))
	}
	for k, v := range want {
		if p.JSONFlat[k] != v {
			t.Errorf("JSONFlat[%q] = %q, want %q", k, p.JSONFlat[k], v)
		}
	}
}

func TestParseRequestBody_JSONScalars(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{`42`, "42"},
		{`1.50`, "1.50"},  // json.Number keeps the literal
		{`1e3`, "1e3"},    // literal preserved
		{`"txt"`, "txt"},  // JSON string, not Go-quoted
		{`true`, "true"},  //
		{`[{"b":2}]`, ""}, // container: no top-level flat entry
	}
	for _, tt := range tests {
		p := engine.ParseRequestBody("application/json", []byte(tt.raw))
		if p.ParseError != "" {
			t.Errorf("ParseRequestBody(%s): ParseError %q", tt.raw, p.ParseError)
			continue
		}
		if got := p.JSONFlat["json"]; got != tt.want {
			t.Errorf("JSONFlat[%s][json] = %q, want %q", tt.raw, got, tt.want)
		}
	}
	// top-level array flattening
	p := engine.ParseRequestBody("application/json", []byte(`["a",{"b":2}]`))
	if p.JSONFlat["json.0"] != "a" || p.JSONFlat["json.1.b"] != "2" {
		t.Errorf("array flatten wrong: %v", p.JSONFlat)
	}
}

func TestParseRequestBody_JSONParseError(t *testing.T) {
	p := engine.ParseRequestBody("application/json", []byte(`{"a":`))
	if p.ParseError == "" {
		t.Error("expected ParseError for truncated JSON")
	}
	if p.JSON != nil || p.JSONFlat != nil {
		t.Error("collections must stay nil on parse error")
	}
	// trailing garbage is a parse error (parser differential guard)
	p = engine.ParseRequestBody("application/json", []byte(`{}{}`))
	if p.ParseError == "" {
		t.Error("expected ParseError for trailing garbage after JSON value")
	}
}

func TestParseRequestBody_ContentTypeNormalization(t *testing.T) {
	p := engine.ParseRequestBody("Application/JSON; charset=utf-8", []byte(`{"ok":1}`))
	if p.ParseError != "" || p.JSONFlat["json.ok"] != "1" {
		t.Errorf("charset/params must be stripped: %+v", p)
	}
	if p.ContentType != "application/json" {
		t.Errorf("ContentType = %q", p.ContentType)
	}
	p = engine.ParseRequestBody("application/vnd.api+json", []byte(`{"ok":1}`))
	if p.JSONFlat["json.ok"] != "1" {
		t.Error("+json suffix content types must parse as JSON")
	}
}

func TestParseRequestBody_Form(t *testing.T) {
	p := engine.ParseRequestBody("application/x-www-form-urlencoded", []byte("a=1&a=2&msg=hi+there&z=%2Fslash"))
	if p.ParseError != "" {
		t.Fatalf("ParseError: %q", p.ParseError)
	}
	if p.Form["a"] != "1,2" {
		t.Errorf("duplicate keys comma-joined: Form[a] = %q, want \"1,2\"", p.Form["a"])
	}
	if p.Form["msg"] != "hi there" {
		t.Errorf("Form[msg] = %q, want \"hi there\"", p.Form["msg"])
	}
	if p.Form["z"] != "/slash" {
		t.Errorf("Form[z] = %q, want \"/slash\"", p.Form["z"])
	}
}

// An invalid escape is read literally, as PHP and Node do, and never hides the
// other fields (url.ParseQuery failed on the whole body: "&x=%zz" turned every
// form condition off).
func TestParseRequestBody_FormInvalidEscapeIsLiteral(t *testing.T) {
	p := engine.ParseRequestBody("application/x-www-form-urlencoded", []byte("a=%zz&cmd=id"))
	if p.ParseError != "" || p.Form["a"] != "%zz" || p.Form["cmd"] != "id" {
		t.Errorf("ParseError %q, Form %v", p.ParseError, p.Form)
	}
}

// buildMultipart constructs a valid multipart/form-data body with one value
// part and two file parts (custom + writer-default content types).
func buildMultipart(t *testing.T) (contentType string, body []byte) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("note", "hello world"); err != nil {
		t.Fatal(err)
	}
	h := map[string][]string{
		"Content-Disposition": {`form-data; name="upload"; filename="shell.php"`},
		"Content-Type":        {"application/x-php"},
	}
	part, err := w.CreatePart(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("<?php system($_GET['c']); ?>")); err != nil {
		t.Fatal(err)
	}
	fw, err := w.CreateFormFile("doc", "report.pdf") // CT application/octet-stream
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("%PDF-1.4 fake")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return w.FormDataContentType(), buf.Bytes()
}

func TestParseRequestBody_Multipart(t *testing.T) {
	ct, raw := buildMultipart(t)
	p := engine.ParseRequestBody(ct, raw)
	if p.ParseError != "" {
		t.Fatalf("ParseError: %q", p.ParseError)
	}
	if p.Multipart["note"] != "hello world" {
		t.Errorf("Multipart[note] = %q", p.Multipart["note"])
	}
	if fn := p.MultipartFilenames["upload"]; fn != "shell.php" {
		t.Errorf("MultipartFilenames[upload] = %q, want shell.php", fn)
	}
	if c := p.MultipartContentTypes["upload"]; c != "application/x-php" {
		t.Errorf("MultipartContentTypes[upload] = %q, want application/x-php", c)
	}
	if p.FilesCount != 2 {
		t.Errorf("FilesCount = %d, want 2", p.FilesCount)
	}
	if !strings.Contains(p.Multipart["upload"], "<?php") {
		t.Errorf("file part content preview missing: %q", p.Multipart["upload"])
	}
	if fn := p.MultipartFilenames["doc"]; fn != "report.pdf" {
		t.Errorf("MultipartFilenames[doc] = %q, want report.pdf", fn)
	}
}

func TestParseRequestBody_MultipartErrors(t *testing.T) {
	// missing boundary
	p := engine.ParseRequestBody("multipart/form-data", []byte("x"))
	if p.ParseError == "" {
		t.Error("expected ParseError for missing boundary")
	}
	// malformed body with a boundary
	p = engine.ParseRequestBody("multipart/form-data; boundary=xyz", []byte("not a multipart body"))
	if p.ParseError == "" {
		t.Error("expected ParseError for malformed multipart body")
	}
}

func TestParseRequestBody_UnknownAndEmptyContentType(t *testing.T) {
	for _, ct := range []string{"text/plain", "application/octet-stream", ""} {
		p := engine.ParseRequestBody(ct, []byte("some raw bytes"))
		if p.ParseError != "" {
			t.Errorf("ct %q: unexpected ParseError %q", ct, p.ParseError)
		}
		if p.JSON != nil || p.JSONFlat != nil || p.Form != nil || p.Multipart != nil ||
			p.MultipartFilenames != nil || p.MultipartContentTypes != nil || p.FilesCount != 0 {
			t.Errorf("ct %q: collections must be nil for unknown content types: %+v", ct, p)
		}
	}
}

func TestParseRequestBody_OversizedGuard(t *testing.T) {
	big := []byte(`{"a":"` + strings.Repeat("x", engine.MaxBodyParseBytes) + `"}`)
	if len(big) <= engine.MaxBodyParseBytes {
		t.Fatalf("test body not oversized: %d", len(big))
	}
	p := engine.ParseRequestBody("application/json", big)
	if p.ParseError == "" {
		t.Error("expected ParseError for oversized body")
	}
	if p.JSONFlat != nil || p.JSON != nil {
		t.Error("collections must stay nil beyond MaxBodyParseBytes (raw matching only)")
	}
	if engine.MaxBodyParseBytes != 64*1024 {
		t.Errorf("MaxBodyParseBytes = %d, want 65536", engine.MaxBodyParseBytes)
	}
}

func TestParseRequestBody_EmptyBody(t *testing.T) {
	p := engine.ParseRequestBody("application/json", nil)
	if p.ParseError != "" || p.JSONFlat != nil {
		t.Errorf("empty body must not parse: %+v", p)
	}
	if p.ContentType != "application/json" {
		t.Errorf("ContentType = %q", p.ContentType)
	}
}
