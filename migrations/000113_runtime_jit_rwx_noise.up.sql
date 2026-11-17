-- 000113_runtime_jit_rwx_noise (runtime-security noise)
--
-- Demo host, 2026-10-16: OWASP Juice Shop (comm "node") raised a CRITICAL
-- incident "mprotect(RWX) — W^X violation", four events in 26 minutes. The
-- kernel marks every mprotect with PROT_WRITE|PROT_EXEC CRITICAL and ingest
-- opens an incident for any stored event at HIGH or above; V8 (WebAssembly
-- code space), the JVM, .NET, PyPy, LuaJIT and Mono do this as part of their
-- JIT.
-- New built-in (priority 45) keeps RWX mprotect by these runtime names at
-- MEDIUM, tagged jit-runtime + unverified-identity (the name is set by the
-- process, so never lower and never a suppress; any other process keeps
-- CRITICAL). The flag a user can edit on a built-in is never written; new
-- rows take the column default (on). Custom rules are not touched. Hosts
-- seeded after this migration get the same rule from builtinRules
-- (trace_rules_builtin.go).

INSERT INTO trace_detection_rules
  (project_id, host_id, name, description, built_in, action, conditions, severity_override, priority, tags)
SELECT s.project_id, s.host_id, 'Downgrade JIT runtime RWX memory', 'Node.js, Deno, Bun, the JVM, .NET, PyPy, LuaJIT and Mono map JIT code writable and executable at once (mprotect with PROT_WRITE|PROT_EXEC). Kept at MEDIUM and tagged, so ordinary JIT activity opens no CRITICAL incident; the name is set by the process, and any other process keeps CRITICAL.', true, 'downgrade', '[{"field":"event_name","op":"eq","value":"mprotect"},{"field":"flags","op":"bit_and","value":2},{"field":"comm","op":"in","value":["node","nodejs","npm","deno","bun","java","C1 CompilerThre","C2 CompilerThre","dotnet",".NET Tiered Com","pypy","pypy3","luajit","mono"]}]'::jsonb, 2, 45, ARRAY(SELECT jsonb_array_elements_text('["jit-runtime","unverified-identity","expected"]'::jsonb))
FROM (SELECT DISTINCT project_id, host_id FROM trace_detection_rules WHERE built_in AND host_id IS NOT NULL) s
WHERE NOT EXISTS (SELECT 1 FROM trace_detection_rules r WHERE r.project_id = s.project_id AND r.host_id = s.host_id AND r.name = 'Downgrade JIT runtime RWX memory' AND r.built_in);
