// Package strutil provides string helpers that avoid deprecated stdlib functions.
package strutil

import (
	"strings"
	"unicode/utf8"
)

// TitleCase capitalizes the first rune of s and lowercases the rest.
func TitleCase(s string) string {
	if s == "" {
		return ""
	}
	r, size := utf8.DecodeRuneInString(s)
	return strings.ToUpper(string(r)) + strings.ToLower(s[size:])
}
