package domain

import (
	"encoding/json"
	"testing"
)

// Three states, and 0 must keep meaning "unset" so that every config already
// stored in the database behaves exactly as before.
func TestResolveTimeoutMs(t *testing.T) {
	cases := []struct {
		name     string
		v, def   int
		want     int
		wantUnlt bool
	}{
		{"unset falls back to default", 0, 30000, 30000, false},
		{"explicit value wins", 5000, 30000, 5000, false},
		{"unlimited resolves to zero", TimeoutUnlimited, 30000, 0, true},
		{"other negatives are treated as unset", -7, 30000, 30000, false},
	}
	for _, c := range cases {
		if got := ResolveTimeoutMs(c.v, c.def); got != c.want {
			t.Errorf("%s: ResolveTimeoutMs(%d, %d) = %d, want %d", c.name, c.v, c.def, got, c.want)
		}
		if got := IsUnlimited(c.v); got != c.wantUnlt {
			t.Errorf("%s: IsUnlimited(%d) = %v, want %v", c.name, c.v, got, c.wantUnlt)
		}
	}
}

// applyProxyDefaults must not overwrite the unlimited sentinel. Before the
// three-state change it used `<= 0`, which silently turned -1 back into 30000.
func TestParseProxyConfigPreservesUnlimited(t *testing.T) {
	raw := []byte(`{"timeouts":{"upstream_ms":-1,"read_ms":-1,"write_ms":-1}}`)
	pc, err := ParseProxyConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pc.Timeouts.UpstreamMs != TimeoutUnlimited {
		t.Errorf("upstream_ms = %d, want %d — defaults overwrote the unlimited sentinel",
			pc.Timeouts.UpstreamMs, TimeoutUnlimited)
	}
	if pc.Timeouts.ReadMs != TimeoutUnlimited || pc.Timeouts.WriteMs != TimeoutUnlimited {
		t.Errorf("read/write = %d/%d, want both %d", pc.Timeouts.ReadMs, pc.Timeouts.WriteMs, TimeoutUnlimited)
	}
}

func TestParseProxyConfigStillDefaultsZero(t *testing.T) {
	pc, err := ParseProxyConfig([]byte(`{"timeouts":{"upstream_ms":0}}`))
	if err != nil {
		t.Fatal(err)
	}
	if pc.Timeouts.UpstreamMs != defProxyUpstreamMs {
		t.Errorf("upstream_ms = %d, want the %d default", pc.Timeouts.UpstreamMs, defProxyUpstreamMs)
	}
}

func TestValidateAcceptsUnlimitedAndRejectsOtherNegatives(t *testing.T) {
	base := func() ProxyConfig {
		pc, _ := ParseProxyConfig(nil)
		return pc
	}

	pc := base()
	pc.Timeouts.UpstreamMs = TimeoutUnlimited
	if err := pc.Validate(); err != nil {
		t.Errorf("unlimited upstream_ms was rejected: %v", err)
	}

	pc = base()
	pc.Timeouts.UpstreamMs = -2
	err := pc.Validate()
	if err == nil {
		t.Fatal("upstream_ms = -2 was accepted; only -1 is a valid sentinel")
	}
	var msg = err.Error()
	if !json.Valid([]byte(`"` + msg + `"`)) {
		t.Logf("message: %s", msg)
	}

	pc = base()
	pc.Timeouts.UpstreamMs = 600001
	if err := pc.Validate(); err == nil {
		t.Error("upstream_ms above the 600000 ceiling was accepted")
	}
}
