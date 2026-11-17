package domain

import "testing"

func TestValidateWebSocketRulesJSON(t *testing.T) {
	for _, input := range []string{
		`{"websocket":null}`,
		`{"websocket":7}`,
		`{"websocket":{"limits":{"max_text_bytes":-1}}}`,
		`{"websocket":{"origin_check":{"enabled":true,"allowed_origins":[]}}}`,
		`{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://ok.test/path"]}}}`,
		`{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://ok.test:bad"]}}}`,
		`{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://ok.test:70000"]}}}`,
		`{"websocket":{"origin_check":{"enabled":null,"allowed_origins":["https://ok.test"]}}}`,
		`{"websocket":{"origin_check":{"enabled":false,"allowed_origins":null}}}`,
		`{"websocket":{"limits":{"max_text_bytes":null}}}`,
	} {
		if err := ValidateWebSocketRulesJSON([]byte(input)); err == nil {
			t.Errorf("%s: want validation error", input)
		}
	}
	for _, input := range []string{
		`{}`,
		`{"websocket":{"enabled":false}}`,
		`{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://ok.test:443"]},"limits":{"max_text_bytes":65536}}}`,
	} {
		if err := ValidateWebSocketRulesJSON([]byte(input)); err != nil {
			t.Errorf("%s: unexpected validation error: %v", input, err)
		}
	}
}
