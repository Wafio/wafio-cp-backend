// Charset normalization: UTF-7 shift sequences
// and NUL-interleaved UTF-16 are decoded before the semantic tokenizers so
// payload hidden in alternate charsets reaches the engines as UTF-8.
package engine

// utf7B64 maps the modified-base64 alphabet used inside UTF-7 shift
// sequences (+...-) back to 6-bit values. '/' is included per RFC 2152; '='
// is not part of the alphabet.
var utf7B64 = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for i := 0; i < len(alpha); i++ {
		t[alpha[i]] = int8(i)
	}
	return t
}()
