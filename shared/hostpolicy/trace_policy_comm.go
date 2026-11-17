package hostpolicy

import (
	"strings"
	"unicode/utf8"
)

const (
	// CommMatchExact: the term equals the whole process name.
	CommMatchExact = "exact"
	// CommMatchWord: the term occurs in the name delimited by a non-letter or
	// the edge of the name ("nc" matches nc and nc.openbsd, not runc or ncat;
	// "python" matches python3). Default for new policies.
	CommMatchWord = "word"
	// CommMatchSubstring: the term occurs anywhere in the name (legacy).
	CommMatchSubstring = "substring"
)

// minNarrowingTermLen: a match_comm or match_filename term shorter than this
// narrows nothing worth skipping kill_acknowledged for ("nc", "/", "sh").
const minNarrowingTermLen = 3

// validCommMatchMode reports whether mode is empty or a known mode.
func validCommMatchMode(mode string) bool {
	switch mode {
	case "", CommMatchExact, CommMatchWord, CommMatchSubstring:
		return true
	}
	return false
}

// DefaultCommMatchMode fills an empty MatchCommMode for a save: the stored
// policy's mode on an update (previous, when known), CommMatchWord for a new
// policy. An explicit mode is left alone.
func DefaultCommMatchMode(p *EnforcementPolicy, previous string) {
	switch {
	case p.MatchCommMode != "":
	case previous != "":
		p.MatchCommMode = previous
	default:
		p.MatchCommMode = CommMatchWord
	}
}

// MatchTerms splits a comma-separated criterion into its non-empty,
// lower-cased, trimmed terms.
func MatchTerms(list string) []string {
	var out []string
	for _, term := range strings.Split(list, ",") {
		if t := strings.TrimSpace(strings.ToLower(term)); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// commNarrows: every term must be at least minNarrowingTermLen characters.
// Terms are OR-ed, so one short term broadens the whole criterion.
func commNarrows(p EnforcementPolicy) bool {
	terms := MatchTerms(p.MatchComm)
	if len(terms) == 0 {
		return false
	}
	for _, t := range terms {
		if utf8.RuneCountInString(t) < minNarrowingTermLen {
			return false
		}
	}
	return true
}

// filenameNarrows: like commNarrows, per FilenameTermNarrows.
func filenameNarrows(p EnforcementPolicy) bool {
	terms := MatchTerms(p.MatchFilename)
	if len(terms) == 0 {
		return false
	}
	for _, t := range terms {
		if !FilenameTermNarrows(t) {
			return false
		}
	}
	return true
}

// commonSystemDirs are directory names nearly every process path runs
// through ("lib" also covers lib32, lib64, libx32 and libexec).
var commonSystemDirs = map[string]bool{
	"usr": true, "bin": true, "sbin": true, "lib": true, "lib32": true, "lib64": true,
	"libx32": true, "libexec": true, "etc": true, "var": true, "tmp": true, "opt": true,
	"home": true, "local": true, "share": true,
}

// FilenameTermNarrows reports whether one match_filename substring term
// selects a meaningful subset of paths. Broad: shorter than
// minNarrowingTermLen, only slashes, a top-level directory prefix (a path
// term with at most one non-empty segment: "/usr/", "/bin", "tmp/"), or made
// only of common system directory names ("lib", "/usr/bin/", "/usr/local/").
func FilenameTermNarrows(t string) bool {
	if utf8.RuneCountInString(t) < minNarrowingTermLen {
		return false
	}
	var segments []string
	for _, s := range strings.Split(t, "/") {
		if s != "" {
			segments = append(segments, s)
		}
	}
	if len(segments) == 0 || (strings.Contains(t, "/") && len(segments) <= 1) {
		return false
	}
	for _, s := range segments {
		if !commonSystemDirs[s] {
			return true
		}
	}
	return false
}

// uidNarrows: UID 0 is every root daemon on the host, not a narrowing.
func uidNarrows(p EnforcementPolicy) bool {
	return p.MatchUID != nil && *p.MatchUID != 0
}
