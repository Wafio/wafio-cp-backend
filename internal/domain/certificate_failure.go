package domain

// CertFailureKeyUnreadable is the code of a stored key that the control plane could not open.
const CertFailureKeyUnreadable = "key_unreadable"

// The codes a failed upload can carry. An agent answers a refused install with one of the first
// five and write_failed; invalid_ack stands for any other answer, and key_unreadable is the control
// plane's own.
var certFailureCodes = []string{"bad_pem", "too_large", "key_mismatch", "leaf_mismatch", "unsupported_key", "write_failed", "invalid_ack", CertFailureKeyUnreadable}

// CertificateFailureText is the text stored for an uploaded certificate that failed with code.
// CertificateFailureCode reads the code back, so the two stay a pair.
func CertificateFailureText(code string) string {
	if code == CertFailureKeyUnreadable {
		return "the stored key cannot be read (" + code + "); upload the certificate again"
	}
	return "the agent refused the certificate (" + code + ")"
}

// CertificateFailureCode returns the code that text was written for, or "" when text is none of the
// phrases of CertificateFailureText. Only a whole match counts: a prefix, a suffix or another case
// is no code.
func CertificateFailureCode(text string) string {
	for _, code := range certFailureCodes {
		if text == CertificateFailureText(code) {
			return code
		}
	}
	return ""
}
