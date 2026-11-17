// Attack taxonomy (CWE, MITRE ATT&CK) for audit trail and SIEM.
package engine

// AttackTaxonomy holds CWE and MITRE ATT&CK technique IDs for a detection.
type AttackTaxonomy struct {
	CWE             string   // e.g. "CWE-89"
	MITRETechniques []string // e.g. ["T1190"]
}
