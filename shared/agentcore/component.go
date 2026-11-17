package agentcore

// AgentComponentInfo is one entry of the security-data status an agent reports
// (CommandAck "secdata:status").
type AgentComponentInfo struct {
	Exists     bool   `json:"exists"`
	SizeBytes  int64  `json:"size_bytes"`
	ModifiedAt string `json:"modified_at"` // RFC3339 or empty
	Path       string `json:"path"`        // absolute path on the agent host
}
