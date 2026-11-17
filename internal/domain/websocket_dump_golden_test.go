package domain

// Rust port oracle for ValidateWebSocketRulesJSON (origins go through
// url.Parse): writes "ok"/"err" per input as JSON lines, which the Rust test
// websocket_differential of wafio-agent-waf (crates/domain) replays. Skipped
// unless WAFIO_GOLDEN_WS_OUT is set:
//
//	WAFIO_GOLDEN_WS_OUT=/tmp/ws.jsonl go test ./internal/domain -run TestWebSocketDumpGolden -count=1
//	GODUMP_WS=/tmp/ws.jsonl cargo test -p wafio-domain websocket_differential   (in wafio-agent-waf)

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestWebSocketDumpGolden(t *testing.T) {
	out := os.Getenv("WAFIO_GOLDEN_WS_OUT")
	if out == "" {
		t.Skip("WAFIO_GOLDEN_WS_OUT not set")
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	enc := json.NewEncoder(w)
	var inputs []string
	schemes := []string{"http", "https", "HTTPS", "ftp", "", "ws", "h-t"}
	hosts := []string{"a.example", "A.EXAMPLE", "", "[::1]", "[fe80::1%25eth0]", "[fe80::1%eth0]", "[1.2.3.4]", "1.2.3.4", "a b", "a%41", "a%2541",
		"a%C3%A9", "é.example", "a_b", "a!b", "a/b", "a?b", "a@b", "@a", "u:p@a", "u@a", "a:", "a:0", "a:80", "a:65535", "a:65536",
		"a:1:2", "a:x", "[::1]:", "[::1]:443", "[::1]x", "[::1", "x[::1]", "a..b", "-a", "a<b>", "a\"b", "a%zz"}
	tails := []string{"", "/", "/p", "?", "?x", "#", "#f", "?#", "//x", " ", "\t", "%"}
	for _, s := range schemes {
		for _, h := range hosts {
			for _, tl := range tails {
				pre := s + "://"
				if s == "" {
					pre = "//"
				}
				inputs = append(inputs, pre+h+tl)
			}
			inputs = append(inputs, s+":"+h, s+":/"+h, " "+s+"://"+h)
		}
	}
	inputs = append(inputs, "*", "", "https://a.example\x7f", "https://a.example\x00", "https://a ", strings.Repeat("a", 300))
	for _, o := range inputs {
		js, _ := json.Marshal(o)
		doc := `{"websocket":{"origin_check":{"enabled":true,"allowed_origins":[` + string(js) + `]}}}`
		res := "ok"
		if ValidateWebSocketRulesJSON([]byte(doc)) != nil {
			res = "err"
		}
		if err := enc.Encode([2]string{base64.StdEncoding.EncodeToString([]byte(doc)), res}); err != nil {
			t.Fatal(err)
		}
	}
	for _, doc := range []string{"", "null", "[]", "{", `{"websocket":null}`, `{"websocket":7}`, `{"websocket":{}}`, `{"Websocket":7}`,
		`{"websocket":{"Enabled":"x"}}`, `{"websocket":{"enabled":null}}`, `{"websocket":{"ENABLED":null}}`,
		`{"websocket":{"Origin_Check":{"enabled":true}}}`, `{"websocket":{"origin_check":{"enabled":true},"origin_check":{"allowed_origins":["https://a"]}}}`,
		`{"websocket":{"Limits":{"max_text_bytes":-1}}}`, `{"websocket":{"limits":{"MAX_TEXT_BYTES":-1}}}`, `{"websocket":{"limits":{"max_text_bytes":1e3}}}`,
		`{"websocket":{"limits":{"max_text_bytes":"1"}}}`, `{"websocket":{"limits":[]}}`, `{"websocket":{"origin_check":{"allowed_origins":[1]}}}`,
		`{"websocket":{"origin_check":{"allowed_origins":[null]}}}`, `{"websocket":{"origin_check":{"enabled":false,"allowed_origins":[]}}}`,
		`{"websocket":{"scan_server_frames":null}}`, `{"websocket":{"limits":{"max_messages_per_min":null}}}`, ` {"websocket":{}} `,
		`{"websocket":{"origin_check":null}}`, `{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://a"]},"limits":null}}`} {
		res := "ok"
		if ValidateWebSocketRulesJSON([]byte(doc)) != nil {
			res = "err"
		}
		if err := enc.Encode([2]string{base64.StdEncoding.EncodeToString([]byte(doc)), res}); err != nil {
			t.Fatal(err)
		}
	}
}
