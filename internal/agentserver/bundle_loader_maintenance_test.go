package agentserver

import "testing"

func TestMaintenanceOn(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{"never configured", `{}`, false},
		{"no value", ``, false},
		{"null", `null`, false},
		{"on", `{"enabled":true,"message":"x","allow_ips":[]}`, true},
		{"off with settings kept", `{"enabled":false,"message":"x"}`, false},
		{"switch is not a boolean", `{"enabled":"true"}`, false},
		{"broken", `{"enabled":tru`, false},
	} {
		if got := maintenanceOn([]byte(tc.raw)); got != tc.want {
			t.Errorf("%s: maintenanceOn(%q) = %v, want %v", tc.name, tc.raw, got, tc.want)
		}
	}
}
