// Java/EL injection enterprise semantic analysis engine.
//
// Architecture:
//
//	Custom Java/EL Tokenizer: purpose-built lexer for injection detection — handles
//	  malformed/partial Java fragments, expression language (EL), OGNL, SpEL,
//	  JNDI lookup strings, and serialized gadget chains gracefully (no external dependency).
//	  Post-tokenization: adjacent ident merge (defeats obfuscation: Run/**/time → Runtime),
//	  unicode escape resolution (\uXXXX), and nested expression extraction.
//
//	Token-stream pattern analysis (10 phases):
//	  Phase 1:  Token-stream evidence (dangerous class/method calls, Runtime.exec, ProcessBuilder,
//	            reflection, class loading, file I/O, network, JDBC, scripting API)
//	  Phase 2:  JNDI injection (jndi:ldap://, jndi:rmi://, jndi:dns://, jndi:iiop://,
//	            Log4Shell nested lookups ${lower:j}, ${env:}, ${sys:}, ${date:})
//	  Phase 3:  Expression Language injection (${...}, #{...}, T(...), @..., %{...})
//	            - Spring SpEL: T(java.lang.Runtime), #rt, new ProcessBuilder(...)
//	            - OGNL: #_memberAccess, #context, @java.lang.Runtime@getRuntime()
//	            - JSP EL: ${pageContext}, ${applicationScope}
//	            - Unified EL: #{bean.method()}, ${fn:}
//	  Phase 4:  Java deserialization (serialized object markers, gadget chains,
//	            Commons Collections, Fastjson, Jackson, XStream, SnakeYAML)
//	  Phase 5:  Class loading & reflection (Class.forName, ClassLoader, defineClass,
//	            Method.invoke, setAccessible, Unsafe, Lookup)
//	  Phase 6:  Obfuscation detection (unicode escapes \uXXXX, string concatenation,
//	            char array construction, reflection-based method invocation, base64)
//	  Phase 7:  Scripting engine (ScriptEngine, Nashorn, GraalVM, Groovy, BeanShell)
//	  Phase 8:  XML/XSLT injection (TransformerFactory, XMLDecoder, DocumentBuilder)
//	  Phase 9:  Template engine injection (Freemarker, Velocity, Thymeleaf, Pebble)
//	  Phase 10: Regex fallback (patterns the tokenizer may miss: encoded payloads, JNDI strings)
//
//	Multi-layer normalization: URL decode (3-pass), unicode escapes (\uXXXX),
//	  hex/octal literals, null byte stripping, string concatenation resolution,
//	  nested expression flattening.
//
// Each detection produces typed evidence with confidence + weight; scoring sums
// weighted evidence against policy thresholds (block/soft).
//
// Detection capabilities:
//   - JNDI injection:         ${jndi:ldap://...}, ${jndi:rmi://...}, all JNDI protocols
//   - Log4Shell:              Nested lookups (${lower:j}${lower:n}${lower:d}${lower:i}),
//     ${env:AWS_SECRET}, ${sys:java.class.path}, obfuscated ${j${::-n}di}
//   - Spring SpEL:            T(java.lang.Runtime).getRuntime().exec(), new ProcessBuilder(),
//     #rt.exec(), #{systemProperties}, SpEL injection in annotations
//   - OGNL injection:         %{#cmd='id',#iswin=...}, #_memberAccess, @Runtime@getRuntime(),
//     #context['com.opensymphony.xwork2.dispatcher.HttpServletResponse']
//   - JSP/Unified EL:        ${pageContext.request}, #{facesContext}, ${applicationScope}
//   - Java deserialization:   rO0AB (base64 marker), aced0005 (hex marker), ObjectInputStream,
//     Commons Collections gadgets, Fastjson (@type), Jackson (enableDefaultTyping),
//     XStream marshalling, SnakeYAML !!constructor
//   - Runtime execution:      Runtime.getRuntime().exec(), ProcessBuilder, Process,
//     java.lang.reflect.Method.invoke()
//   - Class loading:          Class.forName(), ClassLoader.loadClass(), defineClass(),
//     URLClassLoader, Lookup.defineClass()
//   - Reflection abuse:       setAccessible(true), getDeclaredMethod(), getMethod(),
//     getConstructor(), Proxy.newProxyInstance()
//   - File I/O:               FileInputStream, FileOutputStream, RandomAccessFile, Files.readAllBytes()
//   - Network:                Socket, ServerSocket, URL.openConnection(), HttpURLConnection
//   - Scripting engines:      ScriptEngine, Nashorn (load, Java.type), GraalVM polyglot,
//     GroovyShell, BeanShell (bsh.Interpreter)
//   - XML attacks:            TransformerFactory, XMLDecoder, SAXParser entity injection
//   - Template injection:     Freemarker (<#assign>, ${.data_model}), Velocity (#set, $class),
//     Thymeleaf (__${...}__), Pebble ({% ... %})
//   - Obfuscation:            Unicode escapes (\u0052untime), char concat (new String(new char[]{...})),
//     reflection chains, base64 encoded class bytes, string builder
//   - Kotlin scripting:       KotlinScript, javax.script with kotlin
package engine

// ── types ───────────────────────────────────────────────────────────────────────

// JavaSemanticEvidence is a single signal collected during analysis.
type JavaSemanticEvidence struct {
	Signal     string  `json:"signal"`
	Confidence float64 `json:"confidence"`
	Weight     float64 `json:"weight"`
	Location   string  `json:"location"`
	Context    string  `json:"context"`
}

// JavaSemanticSeverity indicates the severity of detected Java injection.
type JavaSemanticSeverity string

const (
	JavaSeverityLow      JavaSemanticSeverity = "low"
	JavaSeverityMedium   JavaSemanticSeverity = "medium"
	JavaSeverityHigh     JavaSemanticSeverity = "high"
	JavaSeverityCritical JavaSemanticSeverity = "critical"
)

// JavaSemanticPolicy configures thresholds for the Java engine.
type JavaSemanticPolicy struct {
	BlockThreshold float64
	SoftThreshold  float64
}

// JavaSemanticInput is the request data to analyze.
type JavaSemanticInput struct {
	Raw      string
	Location string
}

// JavaSemanticReport is the analysis result.
type JavaSemanticReport struct {
	Raw         string
	Normalized  string
	Evidence    []JavaSemanticEvidence
	Score       float64
	Severity    JavaSemanticSeverity
	Block       bool
	Alert       bool
	Primary     string
	BlockThresh float64
	SoftThresh  float64
}

// ── default policy ──────────────────────────────────────────────────────────────

// ── Java/EL token types ─────────────────────────────────────────────────────────

// ── Java/EL tokenizer ───────────────────────────────────────────────────────────

// ── normalization ───────────────────────────────────────────────────────────────

// ── pre-filter ──────────────────────────────────────────────────────────────────

// ── dangerous class/method dictionaries ─────────────────────────────────────────

// ── JNDI / Log4Shell detection ──────────────────────────────────────────────────

// ── Expression Language patterns ────────────────────────────────────────────────

// ── Deserialization patterns ────────────────────────────────────────────────────

// ── Class loading / reflection patterns ─────────────────────────────────────────

// ── Scripting engine patterns ───────────────────────────────────────────────────

// ── Template engine patterns ────────────────────────────────────────────────────

// ── XML/XSLT patterns ──────────────────────────────────────────────────────────

// ── char array / string builder obfuscation ─────────────────────────────────────

// ── main analysis function ──────────────────────────────────────────────────────

// ── Phase 1: Token-stream evidence ──────────────────────────────────────────────

// ── Phase 2: JNDI / Log4Shell ───────────────────────────────────────────────────

// ── Phase 3: Expression Language ────────────────────────────────────────────────

// ── Phase 4: Deserialization ────────────────────────────────────────────────────

// ── Phase 5: Reflection ─────────────────────────────────────────────────────────

// ── Phase 6: Obfuscation ────────────────────────────────────────────────────────

// ── Phase 7: Scripting engines ──────────────────────────────────────────────────

// ── Phase 8: XML/XSLT injection ─────────────────────────────────────────────────

// ── Phase 9: Template engines ───────────────────────────────────────────────────

// ── Phase 10: Regex fallback ────────────────────────────────────────────────────

// ── helpers ─────────────────────────────────────────────────────────────────────
