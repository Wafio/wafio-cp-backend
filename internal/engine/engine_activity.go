package engine

// Which semantic engines a SemanticConfig switches off. A decision records the engines the operator
// switched off for its scope as engine_disabled:<key> marks: information that never raises a verdict. An
// engine is switched off by semantic_policies.<engine>.disabled, a base score of 0, a path exception's
// semantic_override or a tuning rule's skip_semantic (the last two through DisabledEngines). This file
// reads the SemanticConfig and never builds one.

// EngineSet is the set of engines scored by a category base score or a decision-scale base score of
// their own. JWT, GraphQL and the four visibility-only engines are not in it: a switch turns them off
// through DisabledEngines only.
type EngineSet uint32

// Engine bits, in the order of engineSetKeys.
const (
	EngineSQL EngineSet = 1 << iota
	EngineXSS
	EngineCMD
	EnginePHP
	EnginePython
	EngineLFI
	EngineSSRF
	EngineJava
	EngineNoSQL
	EngineSSTI
	EngineXXE
	EngineDeser
	EngineLDAP
	EngineProtoPollution
)

// engineSetKeys maps bit i to its DisabledEngines key.
var engineSetKeys = [...]string{
	"sql", "xss", "cmd", "php", "python", "lfi", "ssrf", "java",
	"nosql", "ssti", "xxe", "deser", "ldap", "proto_pollution",
}

// EngineSetForKey returns the bit of a DisabledEngines key; 0 for a key that
// is not an operator-switchable engine.
func EngineSetForKey(key string) EngineSet {
	for i, k := range engineSetKeys {
		if k == key {
			return 1 << i
		}
	}
	return 0
}

// Has reports whether every engine in e is in s.
func (s EngineSet) Has(e EngineSet) bool { return e != 0 && s&e == e }

// Keys lists the engine keys in s in a fixed order (nil when empty).
func (s EngineSet) Keys() []string {
	if s == 0 {
		return nil
	}
	var out []string
	for i, k := range engineSetKeys {
		if s&(1<<i) != 0 {
			out = append(out, k)
		}
	}
	return out
}

// InactiveEngines reports the engines this config switches off: a
// DisabledEngines entry, or a base score that makes the engine score nothing.
// It mirrors the gates in semanticScanWindow; TestInactiveEnginesMatchScanGating
// fails when the two drift apart.
func (c *SemanticConfig) InactiveEngines() EngineSet {
	var s EngineSet
	for k, off := range c.DisabledEngines {
		if off {
			s |= EngineSetForKey(k)
		}
	}
	// Category-scored engines: a verdict scores its base score, and
	// aggregateSemanticResults drops a verdict scoring 0.
	for _, e := range [...]struct {
		bit  EngineSet
		base int
	}{
		{EngineSQL, c.SQLiBaseScore}, {EngineXSS, c.XSSBaseScore}, {EngineCMD, c.CmdInjectionBaseScore},
		{EnginePHP, c.PHPBaseScore}, {EnginePython, c.PythonBaseScore}, {EngineLFI, c.LFIBaseScore},
		{EngineSSRF, c.SSRFBaseScore}, {EngineJava, c.JavaBaseScore},
	} {
		if e.base <= 0 {
			s |= e.bit
		}
	}
	if resolveSemanticBaseScore(nosqlPolicyBase(c.NoSQLSemanticPolicy), NoSQLBaseScore) <= 0 {
		s |= EngineNoSQL
	}
	if resolveSemanticBaseScore(sstiPolicyBase(c.SSTISemanticPolicy), SSTIBaseScore) <= 0 {
		s |= EngineSSTI
	}
	if resolveSemanticBaseScore(xxePolicyBase(c.XXESemanticPolicy), XXEBaseScore) <= 0 {
		s |= EngineXXE
	}
	if resolveSemanticBaseScore(deserPolicyBase(c.DeserSemanticPolicy), DeserBaseScore) <= 0 {
		s |= EngineDeser
	}
	if p := c.LDAPSemanticPolicy; p != nil && p.BaseScore <= 0 {
		s |= EngineLDAP
	}
	if p := c.ProtoPollutionSemanticPolicy; p != nil && p.BaseScore <= 0 {
		s |= EngineProtoPollution
	}
	return s
}

// EngineKeys are the twenty engine keys an operator can switch off, in the order a decision lists them.
// They are the keys of semantic_policies.<key>.disabled, a path semantic_override and tuning
// skip_semantic.
var EngineKeys = [...]string{
	"sql", "xss", "cmd", "php", "python", "lfi", "ssrf", "java",
	"nosql", "ssti", "xxe", "deser", "ldap", "proto_pollution",
	"jwt", "graphql",
	"header_injection", "open_redirect", "prompt_injection", "anomaly",
}

// SwitchedOffKeys lists the engines this config switches off, for all twenty keys alike: a
// DisabledEngines entry (policy, path override or tuning skip) or a base score of 0. nil when none. A
// decision records them as engine_disabled:<key> marks.
func (c *SemanticConfig) SwitchedOffKeys() []string {
	inactive := c.InactiveEngines()
	var keys []string
	for _, k := range EngineKeys {
		off := c.isDisabled(k) || inactive.Has(EngineSetForKey(k))
		switch k {
		case "jwt":
			off = off || resolveSemanticBaseScore(c.JWTPolicyBaseScore, JWTBaseScore) <= 0
		case "graphql":
			off = off || resolveSemanticBaseScore(c.GraphQLPolicyBaseScore, GraphQLBaseScore) <= 0
		}
		if off {
			keys = append(keys, k)
		}
	}
	return keys
}
