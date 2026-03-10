package cmdutil

import (
	"fmt"
	"strings"
)

// ParseShellTokens splits s into tokens using POSIX shell quoting rules.
//
// Rules applied:
//   - Unquoted whitespace (space, tab, newline, carriage return) separates tokens.
//   - Single-quoted text ('...') is fully literal; no escape sequences are
//     recognised inside single quotes.
//   - Double-quoted text ("...") supports the backslash escapes \", \\, \n, \t,
//     and \r. Any other backslash sequence preserves both characters.
//   - A backslash that appears outside any quoting context escapes the
//     immediately following character.
//   - Adjacent quoted or unquoted spans with no intervening whitespace are
//     concatenated into a single token.
//
// Returns an error if the input contains an unclosed quote or a trailing
// backslash.
func ParseShellTokens(s string) ([]string, error) {
	var tokens []string
	var cur strings.Builder
	inToken := false

	for i := 0; i < len(s); {
		ch := s[i]

		switch {
		case ch == '\'':
			// Single-quoted span: everything is literal until the closing quote.
			inToken = true
			i++ // consume opening quote
			for i < len(s) && s[i] != '\'' {
				cur.WriteByte(s[i])
				i++
			}
			if i >= len(s) {
				return nil, fmt.Errorf("unclosed single quote in alias value")
			}
			i++ // consume closing quote

		case ch == '"':
			// Double-quoted span: recognise a small set of backslash escapes.
			inToken = true
			i++ // consume opening quote
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					i++ // consume backslash
					switch s[i] {
					case '"', '\\':
						cur.WriteByte(s[i])
					case 'n':
						cur.WriteByte('\n')
					case 't':
						cur.WriteByte('\t')
					case 'r':
						cur.WriteByte('\r')
					default:
						// Unknown escape: preserve backslash and the character.
						cur.WriteByte('\\')
						cur.WriteByte(s[i])
					}
				} else {
					cur.WriteByte(s[i])
				}
				i++
			}
			if i >= len(s) {
				return nil, fmt.Errorf("unclosed double quote in alias value")
			}
			i++ // consume closing quote

		case ch == '\\':
			// Backslash outside any quoting context escapes the next character.
			if i+1 >= len(s) {
				return nil, fmt.Errorf("trailing backslash in alias value")
			}
			inToken = true
			i++ // consume backslash
			cur.WriteByte(s[i])
			i++

		case isShellWhitespace(ch):
			// Whitespace outside quotes flushes the current token.
			if inToken {
				tokens = append(tokens, cur.String())
				cur.Reset()
				inToken = false
			}
			i++

		default:
			inToken = true
			cur.WriteByte(ch)
			i++
		}
	}

	if inToken {
		tokens = append(tokens, cur.String())
	}

	return tokens, nil
}

// isShellWhitespace reports whether b is a POSIX shell word-separator byte.
func isShellWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
