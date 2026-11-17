package engine

// proto_pollution_semantic.go — Prototype pollution detection
//
// Prototype pollution is a JavaScript/Node.js attack that manipulates the prototype
// chain of base objects (Object, Function, Array) to inject properties that affect
// all instances.  Common vectors:
//
//   - JSON body:  {"__proto__": {"isAdmin": true}}
//   - Query params:  ?__proto__[admin]=true
//   - URL-encoded:  user[__proto__][admin]=1
//   - constructor:  {"constructor": {"prototype": {"x": 1}}}
//   - defineGetter:  {"__defineGetter__": ...}
//   - Merge/deep-copy gadgets:  {"__proto__": {"polluted": 1}}

// ProtoPollutionBaseScore is calibrated so a single high-confidence hit exceeds
// the default block_threshold (150).
const ProtoPollutionBaseScore = 185

// ProtoPollutionSemanticPolicy controls prototype-pollution engine behaviour.
// BaseScore=0 disables the engine. Defaults: BaseScore=185.
type ProtoPollutionSemanticPolicy struct {
	BaseScore int // multiplier base; 0 = disabled
}
