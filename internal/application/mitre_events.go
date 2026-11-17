package application

// mitreEvent maps a syscall/event_name to a MITRE ATT&CK technique + tactic.
// Mirrors MITRE_BY_EVENT_TYPE in the Runtime Security frontend so incidents
// group by the same technique the UI displays.
type mitreEvent struct {
	technique string
	tactic    string
}

var mitreByEvent = map[string]mitreEvent{
	"execve":       {"T1059", "Execution"},
	"execveat":     {"T1059", "Execution"},
	"clone":        {"T1543", "Persistence"},
	"kill":         {"T1489", "Impact"},
	"openat":       {"T1083", "Discovery"},
	"unlink":       {"T1485", "Impact"},
	"rename":       {"T1222.002", "Defense Evasion"},
	"chmod":        {"T1222.002", "Defense Evasion"},
	"chown":        {"T1222.002", "Defense Evasion"},
	"connect":      {"T1071", "Command and Control"},
	"accept":       {"T1071", "Command and Control"},
	"bind":         {"T1571", "Command and Control"},
	"socket":       {"T1071", "Command and Control"},
	"listen":       {"T1571", "Command and Control"},
	"setuid":       {"T1548.001", "Privilege Escalation"},
	"setgid":       {"T1548.001", "Privilege Escalation"},
	"ptrace":       {"T1055.008", "Defense Evasion"},
	"mount":        {"T1611", "Privilege Escalation"},
	"umount":       {"T1611", "Privilege Escalation"},
	"finit_module": {"T1547.006", "Persistence"},
	"init_module":  {"T1547.006", "Persistence"},
	// Agent loss/shed reports (trace_events_lost, trace_events_shed): a
	// flood that drops or sheds trace events hides activity (Impair
	// Defenses: Indicator Blocking).
	"trace_events_lost": {"T1562.006", "Defense Evasion"},
	"trace_events_shed": {"T1562.006", "Defense Evasion"},
}

// mitreForEvent returns the technique id and tactic for an event_name, or
// ("","") when the event has no MITRE mapping.
func mitreForEvent(eventName string) (technique, tactic string) {
	m, ok := mitreByEvent[eventName]
	if !ok {
		return "", ""
	}
	return m.technique, m.tactic
}
