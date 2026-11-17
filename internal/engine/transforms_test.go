package engine_test

import (
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// TestTransforms_RegistryCompleteness ensures every documented transform name
// resolves to an implementation.
func TestTransforms_RegistryCompleteness(t *testing.T) {
	want := []string{
		"lowercase", "uppercase", "trim", "trim_left", "trim_right",
		"url_decode", "url_decode_uni", "html_entity_decode", "js_decode",
		"css_decode", "base64_decode", "hex_decode", "sql_hex_decode",
		"normalize_path", "normalize_path_win", "compress_whitespace",
		"remove_whitespace", "remove_nulls", "replace_nulls",
		"remove_comments_char", "replace_comments", "cmd_line",
		"escape_seq_decode", "md5", "sha1", "sha256", "length",
	}
	for _, name := range want {
		if _, ok := engine.ValidTransforms[name]; !ok {
			t.Errorf("ValidTransforms missing %q", name)
		}
	}
	if _, ok := engine.ValidTransforms["no_such_transform"]; ok {
		t.Error("ValidTransforms should not contain unknown names")
	}
}

func TestTransforms_HappyPath(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"lowercase", "HeLLo", "hello"},
		{"uppercase", "HeLLo", "HELLO"},
		{"trim", "  x  ", "x"},
		{"trim_left", "  x  ", "x  "},
		{"trim_right", "  x  ", "  x"},
		{"url_decode", "a%20b%2Fc", "a b/c"},
		{"url_decode", "%E2%82%ACuro", "€uro"},
		{"url_decode_uni", "%u0041%42", "AB"},
		{"html_entity_decode", "&lt;a&gt;&#65;&#x42;&amp;", "<a>AB&"},
		{"html_entity_decode", "Tom &amp; Jerry", "Tom & Jerry"},
		{"html_entity_decode", "&nbsp;", "\u00a0"},
		{"js_decode", `\x41\u0042n`, "ABn"},
		{"js_decode", `a\/b\'c`, "a/b'c"},
		{"css_decode", `\41 BC`, "ABC"},
		{"css_decode", `\e9 t`, "ét"},
		{"base64_decode", "aGVsbG8=", "hello"},
		{"base64_decode", "aGVsbG8", "hello"}, // raw (unpadded)
		{"hex_decode", "414243", "ABC"},
		{"sql_hex_decode", "0x4142", "AB"},
		{"sql_hex_decode", "0x4142434445", "ABCDE"},
		{"normalize_path", "/a/../b/./c//d", "/b/c/d"},
		{"normalize_path", "./a", "a"},
		{"normalize_path", "a/../../b", "../b"},
		{"normalize_path_win", `C:\a\..\b`, "C:/b"},
		{"normalize_path_win", `\\windows\\system32`, "/windows/system32"},
		{"compress_whitespace", "a \t\n b", "a b"},
		{"compress_whitespace", "  x", " x"},
		{"remove_whitespace", "a b\tc\nd", "abcd"},
		{"remove_nulls", "a\x00b\x00", "ab"},
		{"replace_nulls", "a\x00b", "a b"},
		{"remove_comments_char", "a/*b*/c--d#e", "abcde"},
		{"replace_comments", "a/*x*/b/*y*/c", "a b c"},
		{"cmd_line", `\"hello  world\"`, "hello world"},
		{"cmd_line", "cat  -r'f  file", "cat -rf file"},
		{"escape_seq_decode", `\n\x41\u0042\101`, "\nABA"}, // \101 octal = 'A'
		{"escape_seq_decode", `tab\there`, "tab\there"},
		{"md5", "hello", "5d41402abc4b2a76b9719d911017c592"},
		{"sha1", "hello", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"},
		{"sha256", "hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
		{"length", "hello", "5"},
		{"length", "héllo", "6"}, // byte length
	}
	for _, tt := range tests {
		t.Run(tt.name+"/"+tt.input, func(t *testing.T) {
			fn, ok := engine.ValidTransforms[tt.name]
			if !ok {
				t.Fatalf("transform %q not registered", tt.name)
			}
			if got := fn(tt.input); got != tt.want {
				t.Errorf("%s(%q) = %q, want %q", tt.name, tt.input, got, tt.want)
			}
		})
	}
}

// TestTransforms_InvalidInputPassthrough — decoding transforms return their
// input unchanged when it is not decodable (best-effort, never an error).
func TestTransforms_InvalidInputPassthrough(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"url_decode", "100%"},
		{"url_decode", "%ZZ"},
		{"url_decode", "a+b"}, // '+' is NOT decoded (path semantics)
		{"url_decode_uni", "%uZZ"},
		{"url_decode_uni", "%u00"},
		{"html_entity_decode", "&unknown;"},
		{"html_entity_decode", "a & b"},
		{"html_entity_decode", "&#x110000;"}, // beyond runes
		{"js_decode", `\xZZ`},
		{"js_decode", `\uZZZZ`},
		{"base64_decode", "!!!"},
		{"base64_decode", "a=b"},
		{"hex_decode", "414"},  // odd length
		{"hex_decode", "zz"},   // not hex
		{"hex_decode", "4g41"}, // not hex
		{"sql_hex_decode", "4142"},
		{"sql_hex_decode", "0x4"},
		{"sql_hex_decode", "0xZZ"},
		{"escape_seq_decode", `\x`},
		{"escape_seq_decode", `\u12`},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/"+tt.input, func(t *testing.T) {
			fn := engine.ValidTransforms[tt.name]
			if got := fn(tt.input); got != tt.input {
				t.Errorf("%s(%q) = %q, want passthrough %q", tt.name, tt.input, got, tt.input)
			}
		})
	}
}
