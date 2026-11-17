package repository

import (
	"testing"
)

func TestParseAgentProcessMeta(t *testing.T) {
	t.Run("empty json fallback for waf", func(t *testing.T) {
		bin, dir, svc, usr := parseAgentProcessMeta(nil, "waf")
		if bin != "/usr/local/bin/wafio-waf-agent" {
			t.Errorf("got %q, want /usr/local/bin/wafio-waf-agent", bin)
		}
		if dir != "/usr/local/bin" {
			t.Errorf("got %q, want /usr/local/bin", dir)
		}
		if svc != "wafio-waf-agent.service" {
			t.Errorf("got %q, want wafio-waf-agent.service", svc)
		}
		if usr != "root" {
			t.Errorf("got %q, want root", usr)
		}
	})

	t.Run("empty json fallback for host", func(t *testing.T) {
		bin, dir, svc, usr := parseAgentProcessMeta([]byte(`{}`), "host")
		if bin != "/usr/local/bin/wafio-host-agent" {
			t.Errorf("got %q, want /usr/local/bin/wafio-host-agent", bin)
		}
		if dir != "/usr/local/bin" {
			t.Errorf("got %q, want /usr/local/bin", dir)
		}
		if svc != "wafio-host-agent.service" {
			t.Errorf("got %q, want wafio-host-agent.service", svc)
		}
		if usr != "root" {
			t.Errorf("got %q, want root", usr)
		}
	})

	t.Run("custom metadata parsed correctly", func(t *testing.T) {
		custom := []byte(`{
			"binary_path": "/opt/custom/bin/agent",
			"install_dir": "/opt/custom/bin",
			"service_name": "custom-agent.service",
			"service_user": "wafio-user"
		}`)
		bin, dir, svc, usr := parseAgentProcessMeta(custom, "waf")
		if bin != "/opt/custom/bin/agent" {
			t.Errorf("got %q, want /opt/custom/bin/agent", bin)
		}
		if dir != "/opt/custom/bin" {
			t.Errorf("got %q, want /opt/custom/bin", dir)
		}
		if svc != "custom-agent.service" {
			t.Errorf("got %q, want custom-agent.service", svc)
		}
		if usr != "wafio-user" {
			t.Errorf("got %q, want wafio-user", usr)
		}
	})
}
