package domain

import "testing"

func TestParseProxyConfigDefaults(t *testing.T) {
	pc, err := ParseProxyConfig([]byte(`{}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pc.Timeouts.UpstreamMs != 30000 || pc.Timeouts.ReadMs != 60000 || pc.Timeouts.WriteMs != 60000 {
		t.Fatalf("timeout defaults wrong: %+v", pc.Timeouts)
	}
	if pc.Timeouts.ConnectMs != 0 {
		t.Fatalf("connect default want 0 got %d", pc.Timeouts.ConnectMs)
	}
	if pc.MaxBodyBytes != 67108864 {
		t.Fatalf("body default wrong: %d", pc.MaxBodyBytes)
	}
	if pc.ReadBuf != 16384 || pc.WriteBuf != 16384 {
		t.Fatalf("buf defaults wrong: %d/%d", pc.ReadBuf, pc.WriteBuf)
	}
	if pc.MaxConns != 512 || pc.ConnWaitMs != 5000 || pc.IdleConnMs != 10000 {
		t.Fatalf("conn defaults wrong: %+v", pc)
	}
	if pc.HostHeader.Mode != "preserve" {
		t.Fatalf("host mode default wrong: %q", pc.HostHeader.Mode)
	}
	// Absent trust_forwarded means the TCP peer is the client.
	if pc.TrustForwarded {
		t.Fatalf("trust_forwarded absent should default false")
	}
}

func TestParseProxyConfigNilIsDefaults(t *testing.T) {
	pc, err := ParseProxyConfig(nil)
	if err != nil {
		t.Fatalf("parse nil: %v", err)
	}
	if pc.TrustForwarded || pc.MaxConns != 512 {
		t.Fatalf("nil should be defaults: %+v", pc)
	}
}

func TestParseProxyConfigTrustForwardedExplicitFalse(t *testing.T) {
	pc, err := ParseProxyConfig([]byte(`{"trust_forwarded":false}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pc.TrustForwarded {
		t.Fatalf("explicit false must stay false")
	}
}

func TestProxyConfigValidate(t *testing.T) {
	cases := []struct {
		name string
		json string
		ok   bool
	}{
		{"valid full", `{"timeouts":{"connect_ms":2000,"upstream_ms":30000,"read_ms":60000,"write_ms":60000},"max_body_bytes":1048576,"read_buf":16384,"write_buf":16384,"max_conns":512,"conn_wait_ms":5000,"idle_conn_ms":10000,"host_header":{"mode":"custom","value":"api.example.com"},"req_headers":{"add":{"X-Foo":"bar"},"remove":["X-Bar"]},"resp_headers":{"add":{},"remove":[]},"trust_forwarded":false}`, true},
		{"timeout too big", `{"timeouts":{"upstream_ms":600001}}`, false},
		{"buf too small", `{"read_buf":1023}`, false},
		{"body too big", `{"max_body_bytes":1073741825}`, false},
		{"max_conns zero", `{"max_conns":0}`, true},
		{"max_conns over", `{"max_conns":65536}`, false},
		{"bad host mode", `{"host_header":{"mode":"weird"}}`, false},
		{"custom no value", `{"host_header":{"mode":"custom","value":"  "}}`, false},
		{"host value crlf", `{"host_header":{"mode":"custom","value":"a\r\nb"}}`, false},
		{"bad header name", `{"req_headers":{"add":{"X Foo":"bar"}}}`, false},
		{"header value crlf", `{"req_headers":{"add":{"X-Foo":"a\r\nb"}}}`, false},
		{"host in add", `{"req_headers":{"add":{"Host":"x"}}}`, false},
		{"too many headers", `{"req_headers":{"remove":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","a1","b1","c1","d1","e1","f1","g1"]}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc, err := ParseProxyConfig([]byte(tc.json))
			if err != nil {
				if tc.ok {
					t.Fatalf("parse failed but expected valid: %v", err)
				}
				return
			}
			verr := pc.Validate()
			if tc.ok && verr != nil {
				t.Fatalf("want valid, got %v", verr)
			}
			if !tc.ok && verr == nil {
				t.Fatalf("want invalid, got nil")
			}
		})
	}
}
