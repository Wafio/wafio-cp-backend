package hostpolicy

import "testing"

// The WAF agent's response cache lives in /var/cache/wafio-waf/. A path
// component in TraceKeepBuiltin makes the kernel keep every open under it
// ahead of shedding, so a busy cache would fill the trace ring. This is also
// why the directory is not under /var/lib/wafio-waf-agent, a kept name.
func TestCacheDirectoryOpensAreNotKept(t *testing.T) {
	const (
		oWronly = 0o1
		oRdwr   = 0o2
		oCreat  = 0o100
		oTrunc  = 0o1000
	)
	paths := []string{
		"/var/cache/wafio-waf",
		"/var/cache/wafio-waf/",
		"/var/cache/wafio-waf/0b6f3c1e-5d2a-4c1e-9a77-2f6f3c1e5d2a/ab/abcdef0123456789",
		"/var/cache/wafio-waf/0b6f3c1e-5d2a-4c1e-9a77-2f6f3c1e5d2a/tmp/fill.0123456789ab",
	}
	for _, path := range paths {
		for _, flags := range []uint32{0, oWronly, oRdwr, oWronly | oCreat | oTrunc} {
			evt := &TraceEvent{EventType: TraceOpen, Filename: path, Flags: flags}
			if TraceOpenKept(evt, TraceKeepBuiltin) {
				t.Errorf("open of %s with flags %#o is kept by the shed exemption", path, flags)
			}
			if got := ClassifyTraceEvent(&TraceEvent{EventType: TraceOpen, Filename: path, Flags: flags, Action: ActionMonitor, Category: "file"}); got != TraceClassNoise {
				t.Errorf("open of %s with flags %#o is class %d, want noise", path, flags, got)
			}
		}
	}
	for _, name := range []string{"var", "cache", "wafio-waf"} {
		if _, ok := TraceKeepBuiltin[name]; ok {
			t.Errorf("%q is a kept name: every open under /var/cache/wafio-waf/ would be kept", name)
		}
	}
}
