// Package strutil provides string helpers that avoid deprecated stdlib functions.
package strutil

import (
	"strings"
	"unicode/utf8"
)

// TitleCase capitalizes the first rune of s and lowercases the rest.
// Replacement for deprecated strings.Title for ASCII-only severity
// strings like "critical" → "Critical". Uses rune-aware decoding so
// multi-byte inputs ("éclair", "über") are not corrupted by
// byte-slicing the leading codepoint in half.
func TitleCase(s string) string {
	if s == "" {
		return ""
	}
	first, size := utf8.DecodeRuneInString(s)
	if first == utf8.RuneError && size <= 1 {
		// Invalid UTF-8 at the start — fall back to the byte-slice
		// path so we still return something rather than mangling.
		return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
	}
	return strings.ToUpper(string(first)) + strings.ToLower(s[size:])
}
