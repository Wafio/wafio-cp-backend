package engine

// ldap_semantic.go — LDAP injection detection
//
// Covers:
//   - LDAP filter injection:  )(uid=*)  )(|(uid=*)  *)(objectClass=*)
//   - Attribute injection:    admin*)(&  admin*)(password=*
//   - Null-byte LDAP          \00 escape abuse
//   - DN injection:           cn=admin,dc=corp,dc=com inside user input
//   - LDAP special chars used as operators
//   - Blind LDAP timing / boolean injection patterns

// LDAPBaseScore is the base score assigned when LDAP injection evidence is found.
// Calibrated to exceed the default block_threshold (150) when confidence is ≥ 0.90.
const LDAPBaseScore = 180

// LDAPSemanticPolicy controls LDAP engine behaviour.
// BaseScore=0 disables the engine. Defaults: BaseScore=180.
type LDAPSemanticPolicy struct {
	BaseScore int // multiplier base; 0 = disabled
}
