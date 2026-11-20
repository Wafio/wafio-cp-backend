package handlers

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// errUploadDuplicateField says that a name appears twice among the top-level fields of an upload.
var errUploadDuplicateField = errors.New("a field appears more than once")

// errUploadBody says that the body of an upload is no JSON object of the shape the endpoint reads.
var errUploadBody = errors.New("invalid upload body")

// uploadFields are the two texts of an upload, copied out of the request body as bytes. The key is in
// one of them, or in both when the user pasted a combined file into the chain, so wipe zeroes them
// whatever way the request ends. They are the only copies: the fields are read in place from the body,
// not through a decoder that would keep its own.
type uploadFields struct {
	chain, key []byte
}

func (u *uploadFields) wipe() {
	clear(u.chain)
	clear(u.key)
}

// readUploadFields cuts chain_pem and key_pem out of the body of an upload. Names are matched without
// regard to case, a name that appears twice (in any case) is errUploadDuplicateField, and other names
// are ignored. An absent field and null give no bytes; any other value than a string is
// errUploadBody, like a body that is not a JSON object.
func readUploadFields(body []byte) (*uploadFields, error) {
	if !json.Valid(body) {
		return nil, errUploadBody
	}
	i := skipJSONSpace(body, 0)
	if i >= len(body) || body[i] != '{' {
		return nil, errUploadBody
	}
	u := &uploadFields{}
	fail := func(err error) (*uploadFields, error) {
		u.wipe()
		return nil, err
	}
	seen := map[string]bool{}
	i = skipJSONSpace(body, i+1)
	for i < len(body) && body[i] == '"' {
		end := jsonStringEnd(body, i)
		var name string
		if json.Unmarshal(body[i:end], &name) != nil {
			return fail(errUploadBody)
		}
		name = strings.ToLower(name)
		if seen[name] {
			return fail(errUploadDuplicateField)
		}
		seen[name] = true
		i = skipJSONSpace(body, skipJSONSpace(body, end)+1) // the colon
		end = jsonValueEnd(body, i)
		if name == "chain_pem" || name == "key_pem" {
			text, ok := unquoteJSONString(body[i:end])
			if !ok {
				return fail(errUploadBody)
			}
			if name == "chain_pem" {
				u.chain = text
			} else {
				u.key = text
			}
		}
		i = skipJSONSpace(body, end)
		if i >= len(body) || body[i] != ',' {
			break
		}
		i = skipJSONSpace(body, i+1)
	}
	return u, nil
}

func skipJSONSpace(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

// jsonStringEnd returns the index after the string literal that starts at b[i]. b is valid JSON.
func jsonStringEnd(b []byte, i int) int {
	for i++; i < len(b); i++ {
		switch b[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return len(b)
}

// jsonValueEnd returns the index after the value that starts at b[i]. b is valid JSON.
func jsonValueEnd(b []byte, i int) int {
	switch b[i] {
	case '"':
		return jsonStringEnd(b, i)
	case '{', '[':
		depth := 0
		for ; i < len(b); i++ {
			switch b[i] {
			case '"':
				i = jsonStringEnd(b, i) - 1
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return i + 1
				}
			}
		}
		return len(b)
	}
	for i < len(b) && !strings.ContainsRune(",}] \t\r\n", rune(b[i])) {
		i++
	}
	return i
}

// unquoteJSONString decodes the JSON string literal raw into bytes without making a Go string, which
// could not be cleared. It reports false when raw is not a string literal. Absent and null give no
// bytes.
func unquoteJSONString(raw []byte) ([]byte, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, true
	}
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, false
	}
	in := raw[1 : len(raw)-1]
	out := make([]byte, 0, len(in))
	fail := func() ([]byte, bool) {
		clear(out)
		return nil, false
	}
	for i := 0; i < len(in); {
		if in[i] != '\\' {
			out = append(out, in[i])
			i++
			continue
		}
		if i+1 >= len(in) {
			return fail()
		}
		switch esc := in[i+1]; esc {
		case '"', '\\', '/':
			out = append(out, esc)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, ok := hex4(in[i+2:])
			if !ok {
				return fail()
			}
			i += 4
			if utf16.IsSurrogate(r) {
				// A high half needs its low half right behind it. Anything else is the replacement
				// character, as in encoding/json.
				pair := utf8.RuneError
				if rest := in[i+2:]; len(rest) >= 6 && rest[0] == '\\' && rest[1] == 'u' {
					if low, ok := hex4(rest[2:]); ok {
						pair = utf16.DecodeRune(r, low)
					}
				}
				if pair != utf8.RuneError {
					i += 6
				}
				r = pair
			}
			out = utf8.AppendRune(out, r)
		default:
			return fail()
		}
		i += 2
	}
	return out, true
}

func hex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var r rune
	for _, c := range b[:4] {
		switch {
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			c = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(c)
	}
	return r, true
}
