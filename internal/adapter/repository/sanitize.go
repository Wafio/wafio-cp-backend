package repository

import (
	"strings"
	"unicode/utf8"
)

// PostgreSQL refuses a NUL byte in text and in jsonb alike. Confirmed against
// PostgreSQL 16.15, where the wording depends on how it arrives: a parameter
// bound by pgx, which is this code's path, is rejected with
//
//	invalid byte sequence for encoding "UTF8": 0x00 (SQLSTATE 22021)
//
// while a literal chr(0) in a query gives "null character not permitted". The
// U+FFFD written in its place is accepted by both columns.
//
// It is not a UTF-8 problem: U+0000 is perfectly valid UTF-8, so the sanitiser
// the agent applies before marshaling proto lets it through untouched.
//
// Every string on a WAF decision is attacker-chosen, and COPY is
// all-or-nothing inside its transaction, so one NUL takes a whole batch of
// decisions with it. The constraint belongs to the database rather than to the
// wire, so it is enforced here: this is the one point both ingest paths pass
// through, the gRPC stream and the legacy HTTP endpoint alike.
//
// NUL becomes U+FFFD rather than being stripped. A NUL in a path is itself an
// attack -- "/etc/passwd\x00.jpg" is the classic null-byte truncation -- and
// deleting it would write "/etc/passwd.jpg" into the log, which reads as a
// request nobody made. Invalid UTF-8 is folded in for the same reason the agent
// does it, so a decision arriving over the HTTP path is held to the same
// standard as one arriving over gRPC.
func sanitizeStoredText(s string) string {
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", "�")
	}
	return strings.ToValidUTF8(s, "�")
}

func sanitizeStoredSlice(in []string) []string {
	for i, v := range in {
		if clean := sanitizeStoredText(v); clean != v {
			out := make([]string, len(in))
			copy(out, in)
			out[i] = clean
			for j := i + 1; j < len(out); j++ {
				out[j] = sanitizeStoredText(out[j])
			}
			return out
		}
	}
	return in
}

// sanitizeStoredMap cleans keys as well as values: the map is stored as jsonb,
// and a NUL in an object key is rejected exactly like one in a value.
func sanitizeStoredMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	for k, v := range in {
		if sanitizeStoredText(k) != k || sanitizeStoredText(v) != v {
			out := make(map[string]string, len(in))
			for k2, v2 := range in {
				out[sanitizeStoredText(k2)] = sanitizeStoredText(v2)
			}
			return out
		}
	}
	return in
}

// maxStoredCoverageLen bounds the coverage column. Agents emit a short
// comma-separated flag list ("field_cap,body_decompress_error"); the legacy
// HTTP ingest accepts any JSON string, so it is capped rather than trusted.
const maxStoredCoverageLen = 512

// capStoredText truncates s to at most n bytes without splitting a rune.
func capStoredText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 {
		if r, size := utf8.DecodeLastRuneInString(s); r != utf8.RuneError || size != 1 {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}

// sanitizeDecision returns d with every stored string made storable.
func sanitizeDecision(d WAFDecision) WAFDecision {
	d.Host = sanitizeStoredText(d.Host)
	d.Method = sanitizeStoredText(d.Method)
	d.URI = sanitizeStoredText(d.URI)
	d.RemoteAddr = sanitizeStoredText(d.RemoteAddr)
	d.CountryCode = sanitizeStoredText(d.CountryCode)
	d.UserAgent = sanitizeStoredText(d.UserAgent)
	d.ContentType = sanitizeStoredText(d.ContentType)
	d.Action = sanitizeStoredText(d.Action)
	d.CWE = sanitizeStoredText(d.CWE)
	d.MatchDetail = sanitizeStoredText(d.MatchDetail)
	d.AnalyzeMethod = sanitizeStoredText(d.AnalyzeMethod)
	d.BodyPreview = sanitizeStoredText(d.BodyPreview)
	d.MatchSource = sanitizeStoredText(d.MatchSource)
	d.RequestBody = sanitizeStoredText(d.RequestBody)
	d.QueryParams = sanitizeStoredText(d.QueryParams)
	d.PayloadType = sanitizeStoredText(d.PayloadType)
	d.Coverage = capStoredText(sanitizeStoredText(d.Coverage), maxStoredCoverageLen)
	if d.Status < 0 || d.Status > 999 {
		d.Status = 0 // not an HTTP status: not recorded
	}
	d.Categories = sanitizeStoredSlice(d.Categories)
	d.RequestHeaders = sanitizeStoredMap(d.RequestHeaders)
	return d
}
