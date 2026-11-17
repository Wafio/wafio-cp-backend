package application

import "testing"

func TestMitreForEvent(t *testing.T) {
	cases := []struct {
		event         string
		wantTechnique string
		wantTactic    string
	}{
		{"setuid", "T1548.001", "Privilege Escalation"},
		{"ptrace", "T1055.008", "Defense Evasion"},
		{"connect", "T1071", "Command and Control"},
		{"openat", "T1083", "Discovery"},
		{"execve", "T1059", "Execution"},
		{"unlink", "T1485", "Impact"},
		{"trace_events_shed", "T1562.006", "Defense Evasion"},
		{"trace_events_lost", "T1562.006", "Defense Evasion"},
		{"totally-unknown-syscall", "", ""},
	}
	for _, c := range cases {
		tech, tac := mitreForEvent(c.event)
		if tech != c.wantTechnique || tac != c.wantTactic {
			t.Errorf("mitreForEvent(%q) = (%q,%q), want (%q,%q)", c.event, tech, tac, c.wantTechnique, c.wantTactic)
		}
	}
}
