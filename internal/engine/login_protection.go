package engine

// LoginProtectionScope is the rate-limit scope of a path exception's login
// protection buckets: the project and the exception's configured path
// pattern. The WAF agent counts attempts under it (with "\x00f", "\x00ip",
// "\x00ua" or "\x00u" appended per bucket type) and the control plane's
// unblock clears it, so every spelling of the path — query string, case,
// escapes, dot segments, path parameters: shares one bucket. The key
// is bounded by the configuration, never by the request.
func LoginProtectionScope(projectID, pattern string) string {
	return "login:" + projectID + ":" + pattern
}

// limitCaseInsensitive reports whether the exception's limits match the path
// case-insensitively: always, unless case_insensitive is explicitly false.
// Folding only adds requests to a limit — on a case-sensitive backend the
// other spellings name no such resource.
func (e *PathExceptionConfig) limitCaseInsensitive() bool {
	return e.CaseInsensitive == nil || *e.CaseInsensitive
}
