package validate

import (
	"unicode"
	"unicode/utf8"
)

// PlainText reports whether s is valid UTF-8 without control or format
// characters: no C0 control (NUL…US, so also TAB, CR, LF, ESC, BEL), no DEL,
// no C1 control (U+0080–U+009F, e.g. U+009B CSI), no Unicode format
// character (category Cf: zero-width and bidi controls U+200B–U+200F,
// U+202A–U+202E, U+2060–U+2069, U+FEFF, soft hyphen …) and no line or
// paragraph separator (U+2028, U+2029).
//
// Names a user picks (hosts, agents, label values) are shown in the
// dashboard and printed by the installer to a root terminal; an ESC/CSI/OSC
// sequence there could rewrite the screen, set the window title or write the
// clipboard (OSC 52), and bidi controls make a name read differently from
// what it is. Letters of every script, digits, punctuation, symbols and the
// plain space stay allowed.
func PlainText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}

// PlainTextMessage is the client message for a name PlainText refuses.
const PlainTextMessage = "must be text without control, formatting or bidi characters"
